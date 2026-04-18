/**
 * Rakshak Ransomware Stress Test
 * 
 * This file creates rapid file system events to test
 * the detection system's velocity-based detection.
 * 
 * Compile: g++ -o stress_test.exe stress_test.cpp -lws2_32
 * Run: stress_test.exe [file_count] [delay_ms]
 */

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <cstdlib>

using namespace std;
using namespace chrono;

const int DEFAULT_FILE_COUNT = 50;
const int DEFAULT_DELAY_MS = 10;

struct FileInfo {
    string path;
    string originalContent;
};

vector<FileInfo> createdFiles;
string testDir;

void printUsage(const char* programName) {
    cout << "Usage: " << programName << " [options]" << endl;
    cout << "Options:" << endl;
    cout << "  <count>    Number of files to create (default: " << DEFAULT_FILE_COUNT << ")" << endl;
    cout << "  <delay>    Delay in ms between operations (default: " << DEFAULT_DELAY_MS << ")" << endl;
    cout << "  --encrypt  Actually encrypt files (DANGEROUS)" << endl;
    cout << "  --dry-run  Simulate only (default)" << endl;
    cout << "  --help     Show this help" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  " << programName << "                    # Test with 50 files, 10ms delay" << endl;
    cout << "  " << programName << " 100 5               # Test with 100 files, 5ms delay" << endl;
    cout << "  " << programName << " 20 50 --dry-run      # 20 files, 50ms delay, dry run" << endl;
}

string generateRandomData(size_t size) {
    static const char charset[] = 
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    string result;
    result.reserve(size);
    
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    for (size_t i = 0; i < size; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

double calculateEntropy(const string& data) {
    if (data.empty()) return 0.0;
    
    int freq[256] = {0};
    for (unsigned char c : data) {
        freq[c]++;
    }
    
    double entropy = 0.0;
    double len = (double)data.length();
    
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = freq[i] / len;
        entropy -= p * log2(p);
    }
    
    return entropy;
}

bool createTestDirectory() {
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        cerr << "[ERROR] Failed to get temp path" << endl;
        return false;
    }
    
    testDir = string(tempPath) + "rakshak_stress_test\\";
    
    if (CreateDirectoryA(testDir.c_str(), NULL) == 0 && GetLastError() != ERROR_ALREADY_EXISTS) {
        cerr << "[ERROR] Failed to create test directory" << endl;
        return false;
    }
    
    cout << "[*] Test directory: " << testDir << endl;
    return true;
}

void createTestFiles(int count) {
    cout << "[*] Creating " << count << " test files..." << endl;
    
    string baseContent = "This is test document content. ";
    for (int i = 0; i < 100; i++) {
        baseContent += baseContent;
    }
    
    for (int i = 0; i < count; i++) {
        string filename = testDir + "test_doc_" + to_string(i) + ".txt";
        FileInfo info;
        info.path = filename;
        info.originalContent = baseContent;
        createdFiles.push_back(info);
        
        HANDLE hFile = CreateFileA(
            filename.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        
        if (hFile == INVALID_HANDLE_VALUE) {
            cerr << "[ERROR] Failed to create file: " << filename << endl;
            continue;
        }
        
        DWORD written;
        WriteFile(hFile, baseContent.c_str(), baseContent.length(), &written, NULL);
        CloseHandle(hFile);
        
        cout << "\r[+] Created " << (i + 1) << "/" << count << " files" << flush;
    }
    cout << endl;
}

void stressTestEntropy(int delayMs, bool actuallyEncrypt) {
    cout << "\n[>] STRESS TEST: High Entropy Detection" << endl;
    cout << "[*] Rapidly writing high-entropy data to " << createdFiles.size() << " files..." << endl;
    
    auto startTime = high_resolution_clock::now();
    int fileCount = 0;
    double maxEntropy = 0.0;
    
    for (const auto& file : createdFiles) {
        string encryptedData = generateRandomData(4096);
        double entropy = calculateEntropy(encryptedData);
        
        if (entropy > maxEntropy) maxEntropy = entropy;
        
        cout << "\r    [ENTROPY: " << entropy << "] " << file.path << flush;
        
        if (actuallyEncrypt) {
            HANDLE hFile = CreateFileA(
                file.path.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hFile, encryptedData.c_str(), encryptedData.length(), &written, NULL);
                CloseHandle(hFile);
            }
        }
        
        Sleep(delayMs);
        fileCount++;
    }
    
    auto endTime = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(endTime - startTime).count();
    
    cout << endl;
    cout << "[*] Files processed: " << fileCount << endl;
    cout << "[*] Total time: " << duration << " ms" << endl;
    cout << "[*] Velocity: " << (fileCount * 1000.0 / duration) << " files/sec" << endl;
    cout << "[*] Max entropy detected: " << maxEntropy << endl;
    
    if (maxEntropy > 7.5) {
        cout << "[!] ENTROPY ABOVE THRESHOLD: " << maxEntropy << " > 7.5" << endl;
    }
}

void stressTestVelocity(int delayMs) {
    cout << "\n[>] STRESS TEST: Velocity-Based Detection" << endl;
    cout << "[*] Rapidly modifying " << createdFiles.size() << " files..." << endl;
    
    auto startTime = high_resolution_clock::now();
    int iteration = 0;
    
    while (duration_cast<seconds>(high_resolution_clock::now() - startTime).count() < 3) {
        for (size_t i = 0; i < createdFiles.size(); i++) {
            string filename = createdFiles[i].path;
            
            HANDLE hFile = CreateFileA(
                filename.c_str(),
                GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            
            if (hFile != INVALID_HANDLE_VALUE) {
                string data = "MODIFIED: " + to_string(iteration) + " - " + generateRandomData(256);
                DWORD written;
                WriteFile(hFile, data.c_str(), data.length(), &written, NULL);
                CloseHandle(hFile);
            }
            
            iteration++;
            cout << "\r    [MODIFY] File " << i << " (iteration " << iteration << ")" << flush;
            
            Sleep(delayMs);
        }
    }
    
    auto endTime = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(endTime - startTime).count();
    
    cout << endl;
    cout << "[*] Total modifications: " << iteration << endl;
    cout << "[*] Total time: " << duration << " ms" << endl;
    cout << "[*] Velocity: " << (iteration * 1000.0 / duration) << " modifications/sec" << endl;
}

void stressTestExtension(int delayMs) {
    cout << "\n[>] STRESS TEST: Extension Change Detection" << endl;
    
    const char* extensions[] = {
        ".encrypted", ".locked", ".crypt", ".enc", 
        ".locky", ".encrypted", ".crypto", ".ransom"
    };
    
    for (size_t i = 0; i < createdFiles.size(); i++) {
        string oldPath = createdFiles[i].path;
        string newExt = extensions[i % (sizeof(extensions) / sizeof(extensions[0]))];
        string newPath = testDir + "test_doc_" + to_string(i) + newExt;
        
        cout << "\r    [RENAME] " << oldPath << " -> " << newExt << flush;
        
        if (MoveFileA(oldPath.c_str(), newPath.c_str())) {
            createdFiles[i].path = newPath;
        }
        
        Sleep(delayMs);
    }
    
    cout << endl;
    cout << "[*] Renamed " << createdFiles.size() << " files" << endl;
}

void cleanup() {
    cout << "\n[*] Cleaning up test files..." << endl;
    
    for (const auto& file : createdFiles) {
        DeleteFileA(file.path.c_str());
    }
    
    RemoveDirectoryA(testDir.c_str());
    
    cout << "[+] Cleanup complete" << endl;
}

int main(int argc, char* argv[]) {
    cout << "==========================================================" << endl;
    cout << "RAKSHAK STRESS TEST" << endl;
    cout << "==========================================================" << endl;
    
    int fileCount = DEFAULT_FILE_COUNT;
    int delayMs = DEFAULT_DELAY_MS;
    bool actuallyEncrypt = false;
    
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        
        if (arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg == "--encrypt") {
            actuallyEncrypt = true;
        }
        else if (arg == "--dry-run") {
            actuallyEncrypt = false;
        }
        else if (isdigit(arg[0])) {
            if (i + 1 < argc && isdigit(argv[i + 1][0])) {
                fileCount = atoi(argv[i]);
                delayMs = atoi(argv[i + 1]);
                i += 2;
            } else {
                fileCount = atoi(argv[i]);
            }
        }
    }
    
    if (actuallyEncrypt) {
        cout << "[!] WARNING: Running in LIVE mode - files WILL be modified!" << endl;
        cout << "[!] Press Ctrl+C to abort within 5 seconds..." << endl;
        Sleep(5000);
    } else {
        cout << "[*] Running in DRY-RUN mode (safe)" << endl;
    }
    
    cout << "[*] Configuration:" << endl;
    cout << "    Files: " << fileCount << endl;
    cout << "    Delay: " << delayMs << " ms" << endl;
    cout << "    Mode: " << (actuallyEncrypt ? "LIVE" : "DRY-RUN") << endl;
    cout << endl;
    
    if (!createTestDirectory()) {
        return 1;
    }
    
    createTestFiles(fileCount);
    
    cout << "\n[>] Starting stress tests..." << endl;
    cout << "[*] Watch the Rakshak dashboard for detection alerts!" << endl;
    
    stressTestEntropy(delayMs, actuallyEncrypt);
    Sleep(1000);
    stressTestExtension(delayMs);
    Sleep(1000);
    stressTestVelocity(delayMs);
    
    if (!actuallyEncrypt) {
        cout << "\n[*] DRY-RUN mode: skipping cleanup" << endl;
    } else {
        cleanup();
    }
    
    cout << "\n[>] Stress test complete!" << endl;
    cout << "[*] Check Rakshak alert history for detection results" << endl;
    
    return 0;
}
