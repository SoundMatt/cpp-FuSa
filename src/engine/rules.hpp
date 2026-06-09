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

} // namespace cpfusa::engine
