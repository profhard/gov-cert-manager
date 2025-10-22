package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// Список госсайтов
var govSites = []string{
	"www.gosuslugi.ru:443",
	"lkfl2.nalog.ru:443",
	"service.fns.ru:443",
	"gosuslugi41.ru:443",
	"www.pfr.gov.ru:443",
	"rosreestr.gov.ru:443",
}

const (
	localCertDir = "/usr/local/share/ca-certificates"
	systemCertDir = "/etc/ssl/certs"
	downloadDir   = "downloaded"
	logDir        = "/var/log/gov-cert-manager"
)

func main() {
	// === Логирование ===
	logFilePath := filepath.Join(logDir, "cert-manager.log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// fallback в текущую директорию
		logFilePath = "cert-manager.log"
	}

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("Не удалось создать лог-файл %s: %v", logFilePath, err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("=== ЗАПУСК ПРОГРАММЫ ===")

	// === Проверка ГОСТ ===
	gostAvailable := isGostEngineAvailable()
	log.Printf("ГОСТ-движок доступен: %v", gostAvailable)

	myApp := app.New()
	myWindow := myApp.NewWindow("Менеджер гос. сертификатов")
	myWindow.Resize(fyne.NewSize(750, 500))

	if !gostAvailable {
		dialog.ShowInformation(
			"Внимание",
			"ГОСТ-движок OpenSSL не обнаружен.\n"+
				"Сайты с ГОСТ-шифрованием могут быть недоступны.\n"+
				"Установите КриптоПро CSP и libgost-engine.",
			myWindow,
		)
		sendNotification("GovCertManager", "ГОСТ-движок недоступен")
	}

	// === Подготовка ===
	os.MkdirAll(downloadDir, 0755)

	var certList []struct {
		Site        string
		CertFile    string
		NeedsUpdate bool
		StatusText  string
	}

	for _, site := range govSites {
		log.Printf("Обработка сайта: %s", site)

		var cert *x509.Certificate
		var err error

		cert, err = fetchRootCert(site)
		if err != nil {
			log.Printf("Стандартное подключение к %s не удалось: %v", site, err)
			if gostAvailable {
				log.Printf("Пробую через ГОСТ для %s...", site)
				cert, err = fetchCertWithGost(site)
				if err != nil {
					log.Printf("ГОСТ тоже не сработал: %v", err)
					continue
				}
			} else {
				continue
			}
		}

		safeName := strings.ReplaceAll(strings.Split(site, ":")[0], ".", "_")
		filename := filepath.Join(downloadDir, safeName+".crt")
		if err := saveCertToPEM(cert, filename); err != nil {
			log.Printf("Ошибка сохранения %s: %v", site, err)
			continue
		}

		installed, reason := isCertInstalled(filename)
		needsUpdate := !installed || reason == "hash_mismatch"

		status := "✅ Установлен"
		if !installed {
			status = "📥 Не установлен"
		} else if reason == "hash_mismatch" {
			status = "🔄 Требуется обновление"
		}

		certList = append(certList, struct {
			Site        string
			CertFile    string
			NeedsUpdate bool
			StatusText  string
		}{site, filename, needsUpdate, status})
	}

	// === GUI ===
	var checkboxes []*widget.Check
	var certFiles []string

	content := container.NewVBox()

	for _, ci := range certList {
		check := widget.NewCheck(fmt.Sprintf("%s — %s", ci.Site, ci.StatusText), nil)
		if ci.NeedsUpdate {
			check.SetChecked(true)
		}
		checkboxes = append(checkboxes, check)
		certFiles = append(certFiles, ci.CertFile)
		content.Add(check)
	}

	installBtn := widget.NewButton("Установить выбранные", func() {
		toInstall := []string{}
		for i, cb := range checkboxes {
			if cb.Checked {
				toInstall = append(toInstall, certFiles[i])
			}
		}

		if len(toInstall) == 0 {
			sendNotification("GovCertManager", "Нет сертификатов для установки")
			return
		}

		for _, f := range toInstall {
			if err := installCert(f); err != nil {
				log.Printf("Ошибка установки %s: %v", f, err)
				continue
			}
			log.Printf("Установлен: %s", f)
		}

		log.Println("Обновление системного хранилища...")
		if err := updateSystemCerts(); err != nil {
			log.Printf("Ошибка update-ca-certificates: %v", err)
			sendNotification("GovCertManager", "Ошибка при обновлении сертификатов!")
		} else {
			log.Println("Сертификаты успешно обновлены")
			sendNotification("GovCertManager", fmt.Sprintf("Установлено %d сертификатов", len(toInstall)))
		}
	})

	content.Add(installBtn)
	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

// --- Вспомогательные функции ---

func sendNotification(title, body string) {
	cmd := exec.Command("notify-send", "-a", "GovCertManager", title, body, "-t", "5000")
	_ = cmd.Run()
}

func isGostEngineAvailable() bool {
	if _, err := exec.LookPath("openssl"); err != nil {
		return false
	}
	cmd := exec.Command("openssl", "engine", "gost")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	outStr := string(output)
	return strings.Contains(outStr, "(gost)") && !strings.Contains(outStr, "unavailable")
}

func fetchRootCert(site string) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", site, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates")
	}
	return chain[len(chain)-1], nil
}

func fetchCertWithGost(hostPort string) (*x509.Certificate, error) {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("openssl", "s_client",
		"-connect", hostPort,
		"-engine", "gost",
		"-cipher", "GOST2012-GOST8912-GOST8912:ECDHE-GOST-GOST89-GOST89",
		"-servername", host,
	)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	stdin, _ := cmd.StdinPipe()
	go func() {
		stdin.Write([]byte("\n"))
		stdin.Close()
	}()

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl failed: %w", err)
	}

	pemBlocks := extractPEMCertificates(out.String())
	if len(pemBlocks) == 0 {
		return nil, fmt.Errorf("no PEM certificates found")
	}

	last := pemBlocks[len(pemBlocks)-1]
	cert, err := x509.ParseCertificate(last.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func extractPEMCertificates(output string) []*pem.Block {
	var blocks []*pem.Block
	lines := strings.Split(output, "\n")
	var current []string
	inCert := false

	for _, line := range lines {
		if strings.Contains(line, "-----BEGIN CERTIFICATE-----") {
			inCert = true
			current = []string{line}
		} else if inCert {
			current = append(current, line)
			if strings.Contains(line, "-----END CERTIFICATE-----") {
				pemData := strings.Join(current, "\n")
				block, _ := pem.Decode([]byte(pemData))
				if block != nil && block.Type == "CERTIFICATE" {
					blocks = append(blocks, block)
				}
				inCert = false
			}
		}
	}
	return blocks
}

func saveCertToPEM(cert *x509.Certificate, filename string) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func isCertInstalled(certFile string) (bool, string) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return false, "missing"
	}

	newHash, err := fileHash(certFile)
	if err != nil {
		return false, "hash_error"
	}

	err = filepath.Walk(systemCertDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		oldHash, _ := fileHash(path)
		if oldHash == newHash {
			return io.EOF
		}
		return nil
	})

	if err == io.EOF {
		return true, "ok"
	}
	return false, "hash_mismatch"
}

func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

func installCert(certFile string) error {
	dest := filepath.Join(localCertDir, filepath.Base(certFile))
	input, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, input, 0644)
}

func updateSystemCerts() error {
	return exec.Command("update-ca-certificates", "--fresh").Run()
}