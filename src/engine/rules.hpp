//fusa:req REQ-FUSA001 REQ-FUSA002 REQ-FUSA003 REQ-FUSA004 REQ-FUSA005
#pragma once

#include "engine.hpp"

namespace cpfusa::engine {

// FUSA001 – Missing project configuration
Rule make_fusa001();
// FUSA002 – No requirements annotations in source
Rule make_fusa002();
// FUSA003 – Safety version not declared
Rule make_fusa003();
// FUSA004 – No test evidence present
Rule make_fusa004();
// FUSA005 – CHANGELOG.md missing or empty
Rule make_fusa005();

// COUP003 — coupling-report.json absent in DO-178C project
Rule make_coup003();
// HARA005 — highest ASIL in hara exceeds project ASIL
Rule make_hara005();
// ISO26262002 — requirements without asil field in ISO 26262 project
Rule make_iso26262002();
// ISO26262003 — qualify-report.json has failures
Rule make_iso26262003();

} // namespace cpfusa::engine
