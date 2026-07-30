#pragma once
// Package cyber provides cpp-FuSa cybersecurity static analysis rules.
//
// Rules are mapped to CWE weaknesses, ISO 21434 cybersecurity requirements,
// and C++-specific security patterns.
//
// Rule catalogue:
//  CYBER001  Weak cryptographic hash (MD5/SHA-1)          CWE-327 // fusa:suppress CYBER001
//  CYBER002  Weak symmetric cipher (DES/3DES/RC4)         CWE-327 // fusa:suppress CYBER002
//  CYBER003  Insecure random (rand/srand)                  CWE-330
//  CYBER004  Unsafe pointer cast (reinterpret_cast)        CWE-242 / MISRA 11.3
//  CYBER005  Command injection (system/popen with var)     CWE-78
//  CYBER006  Hardcoded credential                          CWE-798
//  CYBER007  TLS cert verification disabled                CWE-295
//  CYBER008  Unbounded input (gets/scanf no width)         CWE-120
//  CYBER009  Integer narrowing (static_cast to smaller)    CWE-190 / MISRA 10.3
//  CYBER010  String concat in SQL/OS API call              CWE-22 / CWE-89
//  CYBER011  Unsafe string ops (strcpy/strcat/sprintf)     CWE-120
//  CYBER012  Null pointer dereference risk                 CWE-476
//  CYBER013  Use-after-free pattern (free+use)             CWE-416
//  CYBER014  Double-free pattern                           CWE-415
//  CYBER015  Stack alloca usage                            CWE-121
//  CYBER016  Permissive file mode (0777)                   CWE-732
//  CYBER017  Hardcoded IP address                          CWE-798
//  CYBER018  Format string vulnerability (printf(var))     CWE-134 // fusa:suppress CYBER018
//  CYBER019  TOCTOU race (access+open)                     CWE-362
//  CYBER020  Insecure temp file (tmpnam/tempnam)           CWE-377

#include "cpfusa/fusa.hpp"
#include "../config/config.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace cpfusa::cyber {

struct CyberFinding {
    std::string rule_id;
    std::string cwe;
    Severity    severity;
    std::string message;
    std::string file;
    int         line{0};
    std::string fix;
};

struct CyberReport {
    std::string              project;
    std::string              version;
    std::string              generated_at;
    int                      total_files{0};
    std::vector<CyberFinding> findings;
};

//fusa:req REQ-CYBER001
CyberReport run(const std::filesystem::path& dir,
                const config::ProjectConfig& cfg);

// write_report serialises the CyberReport to cyber-report.json in dir.
Result<std::monostate> write_report(const std::filesystem::path& dir,
                                    const CyberReport& rpt);

} // namespace cpfusa::cyber
