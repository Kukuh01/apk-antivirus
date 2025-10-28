package main

import (
	"bytes"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
)

func main() {
	// Initialize database
	db, err := NewDatabase("./virus_signatures.db")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Initialize handler
	handler := NewHandler(db)

	// Setup router
	r := mux.NewRouter()

	// API Routes
	r.HandleFunc("/api/scan", handler.ScanFile).Methods("POST")
	r.HandleFunc("/api/scan-path", handler.ScanPath).Methods("POST")
	r.HandleFunc("/api/scan-folder", handler.ScanFolder).Methods("POST")
	r.HandleFunc("/api/signatures", handler.GetSignatures).Methods("GET")
	r.HandleFunc("/api/signatures", handler.AddSignature).Methods("POST")
	r.HandleFunc("/api/signatures/{id}", handler.DeleteSignature).Methods("DELETE")
	r.HandleFunc("/api/add-sample", handler.AddSampleFile).Methods("POST")
	r.HandleFunc("/api/stats", handler.GetStats).Methods("GET")

	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	})

	corsHandler := c.Handler(r)

	log.Println("🚀 Antivirus Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", corsHandler))
}

// Database struct and methods
type Database struct {
	db *sql.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS virus_signatures (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			md5_hash TEXT UNIQUE,
			binary_pattern TEXT,
			severity TEXT,
			description TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS scan_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_path TEXT NOT NULL,
			is_infected BOOLEAN,
			virus_name TEXT,
			detection_type TEXT,
			scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return nil, err
	}

	return &Database{db: db}, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) AddVirusSignature(virus *VirusSignature) error {
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO virus_signatures (name, md5_hash, binary_pattern, severity, description)
		VALUES (?, ?, ?, ?, ?)
	`, virus.Name, virus.MD5Hash, virus.BinaryPattern, virus.Severity, virus.Description)
	return err
}

func (d *Database) GetAllSignatures() ([]VirusSignature, error) {
	rows, err := d.db.Query(`
		SELECT id, name, md5_hash, binary_pattern, severity, description, created_at
		FROM virus_signatures
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var signatures []VirusSignature
	for rows.Next() {
		var sig VirusSignature
		err := rows.Scan(&sig.ID, &sig.Name, &sig.MD5Hash, &sig.BinaryPattern,
			&sig.Severity, &sig.Description, &sig.CreatedAt)
		if err != nil {
			continue
		}
		signatures = append(signatures, sig)
	}

	return signatures, nil
}

func (d *Database) DeleteSignature(id int) error {
	_, err := d.db.Exec("DELETE FROM virus_signatures WHERE id = ?", id)
	return err
}

func (d *Database) AddScanHistory(result *ScanResult) error {
	_, err := d.db.Exec(`
		INSERT INTO scan_history (file_path, is_infected, virus_name, detection_type)
		VALUES (?, ?, ?, ?)
	`, result.FilePath, result.IsInfected, result.VirusName, result.DetectionType)
	return err
}

func (d *Database) GetStats() (Stats, error) {
	var stats Stats

	// Total signatures
	err := d.db.QueryRow("SELECT COUNT(*) FROM virus_signatures").Scan(&stats.TotalSignatures)
	if err != nil {
		return stats, err
	}

	// Total scans
	err = d.db.QueryRow("SELECT COUNT(*) FROM scan_history").Scan(&stats.TotalScans)
	if err != nil {
		return stats, err
	}

	// Threats detected
	err = d.db.QueryRow("SELECT COUNT(*) FROM scan_history WHERE is_infected = 1").Scan(&stats.ThreatsDetected)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// Models
type VirusSignature struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	MD5Hash       string    `json:"md5_hash"`
	BinaryPattern string    `json:"binary_pattern"`
	Severity      string    `json:"severity"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
}

type ScanResult struct {
	FilePath        string    `json:"file_path"`
	IsInfected      bool      `json:"is_infected"`
	VirusName       string    `json:"virus_name,omitempty"`
	DetectionType   string    `json:"detection_type,omitempty"`
	ScanTime        time.Time `json:"scan_time"`
	FileSize        int64     `json:"file_size"`
	QuarantinedPath string    `json:"quarantined_path,omitempty"`
}

type Stats struct {
	TotalSignatures int `json:"total_signatures"`
	TotalScans      int `json:"total_scans"`
	ThreatsDetected int `json:"threats_detected"`
}

// Scanner implementations
type MD5Scanner struct {
	signatures map[string]string
}

func NewMD5Scanner() *MD5Scanner {
	return &MD5Scanner{
		signatures: make(map[string]string),
	}
}

func (s *MD5Scanner) LoadSignatures(sigs map[string]string) {
	s.signatures = sigs
}

func (s *MD5Scanner) CalculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *MD5Scanner) ScanFile(filePath string) (bool, string, error) {
	md5Hash, err := s.CalculateMD5(filePath)
	if err != nil {
		return false, "", err
	}

	if virusName, found := s.signatures[md5Hash]; found {
		return true, virusName, nil
	}

	return false, "", nil
}

type BinaryScanner struct {
	patterns map[string]string
}

func NewBinaryScanner() *BinaryScanner {
	return &BinaryScanner{
		patterns: make(map[string]string),
	}
}

func (s *BinaryScanner) LoadPatterns(patterns map[string]string) {
	s.patterns = patterns
}

func (s *BinaryScanner) ScanFile(filePath string) (bool, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, "", err
	}
	defer file.Close()

	// Read first 10MB for pattern matching
	buffer := make([]byte, 10*1024*1024)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return false, "", err
	}
	content := buffer[:n]

	for pattern, virusName := range s.patterns {
		patternBytes, err := hex.DecodeString(pattern)
		if err != nil {
			continue
		}

		if bytes.Contains(content, patternBytes) {
			return true, virusName, nil
		}
	}

	return false, "", nil
}

// API Handler
type Handler struct {
	db            *Database
	md5Scanner    *MD5Scanner
	binaryScanner *BinaryScanner
}

func NewHandler(db *Database) *Handler {
	h := &Handler{
		db:            db,
		md5Scanner:    NewMD5Scanner(),
		binaryScanner: NewBinaryScanner(),
	}

	h.loadSignatures()
	return h
}

func (h *Handler) loadSignatures() {
	signatures, err := h.db.GetAllSignatures()
	if err != nil {
		log.Println("Error loading signatures:", err)
		return
	}

	md5Sigs := make(map[string]string)
	binSigs := make(map[string]string)

	for _, sig := range signatures {
		if sig.MD5Hash != "" {
			md5Sigs[sig.MD5Hash] = sig.Name
		}
		if sig.BinaryPattern != "" {
			binSigs[sig.BinaryPattern] = sig.Name
		}
	}

	h.md5Scanner.LoadSignatures(md5Sigs)
	h.binaryScanner.LoadPatterns(binSigs)
}

// func (h *Handler) ScanFile(w http.ResponseWriter, r *http.Request) {
// 	var req struct {
// 		FilePath string `json:"file_path"`
// 	}

// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}

// 	fileInfo, err := os.Stat(req.FilePath)
// 	if err != nil {
// 		http.Error(w, "File not found", http.StatusNotFound)
// 		return
// 	}

// 	result := ScanResult{
// 		FilePath:   req.FilePath,
// 		IsInfected: false,
// 		ScanTime:   time.Now(),
// 		FileSize:   fileInfo.Size(),
// 	}

// 	// Try MD5 scan
// 	infected, virusName, _ := h.md5Scanner.ScanFile(req.FilePath)
// 	if infected {
// 		result.IsInfected = true
// 		result.VirusName = virusName
// 		result.DetectionType = "MD5"
// 	} else {
// 		// Try binary scan
// 		infected, virusName, _ = h.binaryScanner.ScanFile(req.FilePath)
// 		if infected {
// 			result.IsInfected = true
// 			result.VirusName = virusName
// 			result.DetectionType = "Binary Pattern"
// 		}
// 	}

// 	// Save to history
// 	h.db.AddScanHistory(&result)

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(result)
// }

func (h *Handler) ScanFile(w http.ResponseWriter, r *http.Request) {
	// 1. Batasi ukuran upload (misalnya 50 MB)
	const maxUploadSize = 50 << 20 // 50 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		log.Println("Error parsing multipart form:", err)
		http.Error(w, "failed parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 2. Ambil file dari form data
	file, fh, err := r.FormFile("file")
	if err != nil {
		log.Println("Error retrieving file from form:", err)
		http.Error(w, "file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 3. Buat file sementara di server
	tempFile, err := os.CreateTemp("", "scan-*.tmp")
	if err != nil {
		log.Println("Error creating temp file:", err)
		http.Error(w, "failed create temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Pastikan file ditutup
	defer tempFile.Close() // Tetap tutup file
	// defer os.Remove(tempFile.Name()) // <-- UBAH: HAPUS BARIS INI!

	// 4. Salin isi file yang di-upload ke file sementara
	if _, err := io.Copy(tempFile, file); err != nil {
		log.Println("Error copying to temp file:", err)
		http.Error(w, "failed write temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Dapatkan path file sementara
	tempFilePath := tempFile.Name()

	// Tutup file agar scanner bisa membukanya
	if err := tempFile.Close(); err != nil {
		log.Println("Error closing temp file before scan:", err)
		http.Error(w, "failed to close temp file before scan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 5. Siapkan hasil scan (gunakan nama file asli dari upload)
	result := ScanResult{
		FilePath:   fh.Filename, // Laporkan nama file asli
		IsInfected: false,
		ScanTime:   time.Now(),
		FileSize:   fh.Size, // Ambil ukuran dari file header
	}

	infected, virusName, _ := h.md5Scanner.ScanFile(tempFilePath)
	if infected {
		result.IsInfected = true
		result.VirusName = virusName
		result.DetectionType = "MD5"
	} else {
		infected, virusName, _ = h.binaryScanner.ScanFile(tempFilePath)
		if infected {
			result.IsInfected = true
			result.VirusName = virusName
			result.DetectionType = "Binary Pattern"
		}
	}

	h.db.AddScanHistory(&result)

	if result.IsInfected {
		const quarantineDir = "./quarantine"

		if err := os.MkdirAll(quarantineDir, 0755); err != nil {
			log.Println("Error creating quarantine directory:", err)
			os.Remove(tempFilePath)
		} else {
			newName := fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(fh.Filename))
			newPath := filepath.Join(quarantineDir, newName)

			err := func() error {
				srcFile, err := os.Open(tempFilePath)
				if err != nil {
					return fmt.Errorf("gagal buka sumber (%s): %w", tempFilePath, err)
				}
				defer srcFile.Close()

				dstFile, err := os.Create(newPath)
				if err != nil {
					return fmt.Errorf("gagal buat tujuan (%s): %w", newPath, err)
				}
				defer dstFile.Close()

				if _, err := io.Copy(dstFile, srcFile); err != nil {
					os.Remove(newPath)
					return fmt.Errorf("gagal menyalin data: %w", err)
				}

				return nil
			}()

			if err != nil {
				log.Printf("Error moving file to quarantine (copy/delete): %v", err)
			} else {
				log.Println("File quarantined to:", newPath)
				result.QuarantinedPath = newPath
			}

			os.Remove(tempFilePath)
		}
	} else {
		os.Remove(tempFilePath)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) ScanPath(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FilePath string `json:"file_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fileInfo, err := os.Stat(req.FilePath)
	if err != nil {
		log.Println("File not found:", req.FilePath, err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	result := ScanResult{
		FilePath:   req.FilePath,
		IsInfected: false,
		ScanTime:   time.Now(),
		FileSize:   fileInfo.Size(),
	}

	infected, virusName, _ := h.md5Scanner.ScanFile(req.FilePath)
	if infected {
		result.IsInfected = true
		result.VirusName = virusName
		result.DetectionType = "MD5"
	} else {
		infected, virusName, _ = h.binaryScanner.ScanFile(req.FilePath)
		if infected {
			result.IsInfected = true
			result.VirusName = virusName
			result.DetectionType = "Binary Pattern"
		}
	}

	h.db.AddScanHistory(&result)

	if result.IsInfected {
		const quarantineDir = "./quarantine"
		if err := os.MkdirAll(quarantineDir, 0755); err != nil {
			log.Println("Error creating quarantine directory:", err)
		} else {
			newName := fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(req.FilePath))
			newPath := filepath.Join(quarantineDir, newName)

			err := os.Rename(req.FilePath, newPath)
			if err != nil {
				log.Printf("os.Rename failed (%v), falling back to Copy-then-Delete", err)

				copyErr := func() error {
					srcFile, err := os.Open(req.FilePath)
					if err != nil {
						return err
					}
					defer srcFile.Close()

					dstFile, err := os.Create(newPath)
					if err != nil {
						return err
					}
					defer dstFile.Close()

					if _, err := io.Copy(dstFile, srcFile); err != nil {
						os.Remove(newPath)
						return err
					}
					return nil
				}()

				if copyErr == nil {
					os.Remove(req.FilePath)
					log.Println("File quarantined (via Copy) to:", newPath)
					result.QuarantinedPath = newPath
				} else {
					log.Println("Fallback Copy-then-Delete failed:", copyErr)
				}
			} else {
				log.Println("File quarantined (via Rename) to:", newPath)
				result.QuarantinedPath = newPath
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) ScanFolder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FolderPath string `json:"folder_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var results []ScanResult

	err := filepath.Walk(req.FolderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error mengakses path %q: %v\n", path, err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		result := ScanResult{
			FilePath:   path,
			IsInfected: false,
			ScanTime:   time.Now(),
			FileSize:   info.Size(),
		}

		infected, virusName, _ := h.md5Scanner.ScanFile(path)
		if infected {
			result.IsInfected = true
			result.VirusName = virusName
			result.DetectionType = "MD5"
		} else {
			infected, virusName, _ = h.binaryScanner.ScanFile(path)
			if infected {
				result.IsInfected = true
				result.VirusName = virusName
				result.DetectionType = "Binary Pattern"
			}
		}

		if result.IsInfected {
			const quarantineDir = "./quarantine"
			if err := os.MkdirAll(quarantineDir, 0755); err != nil {
				log.Printf("Error creating quarantine directory (untuk %s): %v", path, err)
			} else {
				newName := fmt.Sprintf("%d-%s", time.Now().UnixNano(), filepath.Base(path))
				newPath := filepath.Join(quarantineDir, newName)

				err := os.Rename(path, newPath)
				if err != nil {
					log.Printf("os.Rename failed for %s (%v), falling back to Copy-then-Delete", path, err)

					copyErr := func() error {
						srcFile, err := os.Open(path)
						if err != nil {
							return err
						}
						defer srcFile.Close()

						dstFile, err := os.Create(newPath)
						if err != nil {
							return err
						}
						defer dstFile.Close()

						if _, err := io.Copy(dstFile, srcFile); err != nil {
							os.Remove(newPath)
							return err
						}
						return nil
					}()

					if copyErr == nil {
						os.Remove(path)
						log.Println("File quarantined (via Copy) to:", newPath)
						result.QuarantinedPath = newPath
					} else {
						log.Printf("Fallback Copy-then-Delete failed for %s: %v", path, copyErr)
					}
				} else {
					log.Println("File quarantined (via Rename) to:", newPath)
					result.QuarantinedPath = newPath
				}
			}
		}

		results = append(results, result)
		h.db.AddScanHistory(&result)

		return nil
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (h *Handler) GetSignatures(w http.ResponseWriter, r *http.Request) {
	signatures, err := h.db.GetAllSignatures()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signatures)
}

func (h *Handler) AddSignature(w http.ResponseWriter, r *http.Request) {
	var virus VirusSignature

	if err := json.NewDecoder(r.Body).Decode(&virus); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.db.AddVirusSignature(&virus); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.loadSignatures()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Signature added successfully"})
}

func (h *Handler) DeleteSignature(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := h.db.DeleteSignature(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.loadSignatures()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Signature deleted successfully"})
}

func (h *Handler) AddSampleFile(w http.ResponseWriter, r *http.Request) {
	// Batasi ukuran upload (misalnya 50 MB)
	const maxUploadSize = 50 << 20 // 50 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "failed parse multipart form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, fh, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Optional: read other form fields
	name := r.FormValue("name")
	if name == "" {
		name = fh.Filename
	}
	severity := r.FormValue("severity")
	description := r.FormValue("description")

	// Ensure quarantine dir exists
	quarantineDir := "./quarantine"
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		http.Error(w, "failed create quarantine dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create quarantine file (unique name)
	tmpName := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + filepath.Base(fh.Filename)
	tmpPath := filepath.Join(quarantineDir, tmpName)

	outFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // no-exec
	if err != nil {
		http.Error(w, "failed create quarantine file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	// Compute MD5 and capture first N bytes for binary pattern while streaming
	hasher := md5.New()
	const patternLen = 256 // ambil 256 byte pertama; ubah sesuai kebutuhan
	firstBytes := make([]byte, 0, patternLen)
	buf := make([]byte, 32*1024)

	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// write to quarantine file
			if _, err := outFile.Write(chunk); err != nil {
				// cleanup file if write failed
				outFile.Close()
				os.Remove(tmpPath)
				http.Error(w, "failed write file: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// update md5
			if _, err := hasher.Write(chunk); err != nil {
				outFile.Close()
				os.Remove(tmpPath)
				http.Error(w, "hash error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			// collect first bytes
			if len(firstBytes) < patternLen {
				need := patternLen - len(firstBytes)
				if need > n {
					need = n
				}
				firstBytes = append(firstBytes, chunk[:need]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			outFile.Close()
			os.Remove(tmpPath)
			http.Error(w, "read error: "+readErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	md5sum := hex.EncodeToString(hasher.Sum(nil))
	binaryPattern := hex.EncodeToString(firstBytes)

	// Insert to DB: only md5 and binary_pattern (with metadata)
	virus := &VirusSignature{
		Name:          name,
		MD5Hash:       md5sum,
		BinaryPattern: binaryPattern,
		Severity:      severity,
		Description:   description,
	}

	if err := h.db.AddVirusSignature(virus); err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		http.Error(w, "db insert error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.loadSignatures()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":        "Sample added successfully",
		"md5":            md5sum,
		"binary_pattern": binaryPattern,
	})
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
