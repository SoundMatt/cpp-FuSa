//fusa:test REQ-REQ001 REQ-REQ002 REQ-REQ003
#include <catch2/catch_all.hpp>
#include "trace/trace.hpp"
#include "testutil/testutil.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

using namespace cpfusa;
using namespace cpfusa::testutil;

// ─── load_requirements / save_requirements ────────────────────────────────────

TEST_CASE("req: load from empty dir returns empty vector", "[req][req001]") {
    TempDir tmp;
    auto r = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).empty());
}

TEST_CASE("req: save then load round-trips requirements", "[req][req001]") {
    TempDir tmp;
    std::vector<trace::Requirement> reqs;
    reqs.push_back({"REQ-001", "Title One", "Desc one", "ISO 26262", "safety"});
    reqs.push_back({"REQ-002", "Title Two", "Desc two", "IEC 61508", "info"});
    REQUIRE(trace::save_requirements(tmp.path(), reqs));
    auto loaded = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(loaded));
    const auto& v = value_of(loaded);
    REQUIRE(v.size() == 2);
    REQUIRE(v[0].id    == "REQ-001");
    REQUIRE(v[0].title == "Title One");
    REQUIRE(v[1].id    == "REQ-002");
    REQUIRE(v[1].standard_ref == "IEC 61508");
}

TEST_CASE("req: save writes canonical {requirements:[]} format (spec 1.2.2)", "[req][req001]") {
    TempDir tmp;
    std::vector<trace::Requirement> reqs;
    reqs.push_back({"REQ-007", "My req", "", "", "safety"});
    REQUIRE(trace::save_requirements(tmp.path(), reqs));
    std::ifstream f(tmp.path() / ".fusa-reqs.json");
    auto j = nlohmann::json::parse(f);
    REQUIRE(j.contains("requirements"));
    REQUIRE(j["requirements"].is_array());
    REQUIRE(j["requirements"].size() == 1);
    REQUIRE(j["requirements"][0]["id"] == "REQ-007");
}

TEST_CASE("req: load accepts legacy flat-array format", "[req][req001]") {
    TempDir tmp;
    tmp.write(".fusa-reqs.json",
        R"([{"id":"REQ-OLD","title":"Old","description":"","standard_ref":"","severity":"safety"}])");
    auto r = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(r));
    REQUIRE(value_of(r).size() == 1);
    REQUIRE(value_of(r)[0].id == "REQ-OLD");
}

TEST_CASE("req: save_requirements returns false on unwritable path", "[req][req001]") {
    auto bad = std::filesystem::path("/nonexistent_dir_that_cannot_exist_xyz");
    std::vector<trace::Requirement> reqs;
    REQUIRE_FALSE(trace::save_requirements(bad, reqs));
}

// ─── export_csv ───────────────────────────────────────────────────────────────

TEST_CASE("req: export_csv has header row", "[req][req002]") {
    std::vector<trace::Requirement> reqs;
    auto csv = trace::export_csv(reqs);
    REQUIRE(csv.find("id,title") != std::string::npos);
    REQUIRE(csv.find("description") != std::string::npos);
    REQUIRE(csv.find("standard_ref") != std::string::npos);
    REQUIRE(csv.find("severity") != std::string::npos);
}

TEST_CASE("req: export_csv produces one row per requirement", "[req][req002]") {
    std::vector<trace::Requirement> reqs;
    reqs.push_back({"REQ-A", "Alpha", "Desc alpha", "ISO 26262", "safety"});
    reqs.push_back({"REQ-B", "Beta",  "Desc beta",  "IEC 61508", "info"});
    auto csv = trace::export_csv(reqs);
    // 1 header + 2 data rows + trailing newline = 3 non-empty lines
    std::istringstream ss(csv);
    std::string line;
    int count = 0;
    while (std::getline(ss, line)) if (!line.empty()) ++count;
    REQUIRE(count == 3);
}

TEST_CASE("req: export_csv escapes commas in field values", "[req][req002]") {
    std::vector<trace::Requirement> reqs;
    reqs.push_back({"REQ-C", "Title,with,commas", "Desc", "", "safety"});
    auto csv = trace::export_csv(reqs);
    // id field must be intact
    REQUIRE(csv.find("REQ-C") != std::string::npos);
    // commas inside title must be escaped (replaced with semicolons)
    std::istringstream ss(csv);
    std::string header, datarow;
    std::getline(ss, header);
    std::getline(ss, datarow);
    // column 1 (title) should not contain commas
    std::istringstream row_ss(datarow);
    std::string id_field, title_field;
    std::getline(row_ss, id_field,    ',');
    std::getline(row_ss, title_field, ',');
    REQUIRE(title_field.find(',') == std::string::npos);
}

TEST_CASE("req: export_csv empty requirements yields only header", "[req][req002]") {
    auto csv = trace::export_csv({});
    std::istringstream ss(csv);
    std::string line;
    int count = 0;
    while (std::getline(ss, line)) if (!line.empty()) ++count;
    REQUIRE(count == 1);
}

// ─── import_csv ───────────────────────────────────────────────────────────────

TEST_CASE("req: import_csv round-trips through export_csv", "[req][req003]") {
    TempDir tmp;
    std::vector<trace::Requirement> original;
    original.push_back({"REQ-X", "X title", "X desc", "DO-178C", "safety"});
    original.push_back({"REQ-Y", "Y title", "Y desc", "ISO 26262", "info"});

    auto csv = trace::export_csv(original);
    auto csv_path = tmp.path() / "reqs.csv";
    tmp.write("reqs.csv", csv);

    std::vector<trace::Requirement> loaded;
    auto result = trace::import_csv(csv_path, loaded);
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result) == 2);
    REQUIRE(loaded.size() == 2);
    REQUIRE(loaded[0].id    == "REQ-X");
    REQUIRE(loaded[0].title == "X title");
    REQUIRE(loaded[1].id    == "REQ-Y");
    REQUIRE(loaded[1].standard_ref == "ISO 26262");
}

TEST_CASE("req: import_csv skips duplicate ids", "[req][req003]") {
    TempDir tmp;
    std::string csv =
        "id,title,description,standard_ref,severity\n"
        "REQ-DUP,First,d1,ISO 26262,safety\n"
        "REQ-DUP,Second,d2,IEC 61508,info\n"
        "REQ-NEW,Third,d3,DO-178C,safety\n";
    tmp.write("reqs.csv", csv);

    std::vector<trace::Requirement> existing;
    existing.push_back({"REQ-DUP", "Pre-existing", "", "", "safety"});

    auto result = trace::import_csv(tmp.path() / "reqs.csv", existing);
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result) == 1); // only REQ-NEW added
    REQUIRE(existing.size() == 2);  // REQ-DUP original + REQ-NEW
    REQUIRE(existing[1].id == "REQ-NEW");
}

TEST_CASE("req: import_csv returns error for missing file", "[req][req003]") {
    std::vector<trace::Requirement> reqs;
    auto result = trace::import_csv("/nonexistent/path/reqs.csv", reqs);
    REQUIRE_FALSE(is_ok(result));
    REQUIRE_FALSE(error_of(result).empty());
}

TEST_CASE("req: import_csv skips blank lines", "[req][req003]") {
    TempDir tmp;
    std::string csv =
        "id,title,description,standard_ref,severity\n"
        "\n"
        "REQ-Z,Z title,Z desc,ISO 21434,cybersecurity\n"
        "\n";
    tmp.write("reqs.csv", csv);
    std::vector<trace::Requirement> reqs;
    auto result = trace::import_csv(tmp.path() / "reqs.csv", reqs);
    REQUIRE(is_ok(result));
    REQUIRE(value_of(result) == 1);
    REQUIRE(reqs[0].severity == "cybersecurity");
}

TEST_CASE("req: import_csv default severity is safety when field missing", "[req][req003]") {
    TempDir tmp;
    std::string csv =
        "id,title,description,standard_ref,severity\n"
        "REQ-NS,No sev,desc,ref,\n";
    tmp.write("reqs.csv", csv);
    std::vector<trace::Requirement> reqs;
    auto result = trace::import_csv(tmp.path() / "reqs.csv", reqs);
    REQUIRE(is_ok(result));
    REQUIRE(reqs[0].severity == "safety");
}

// ─── save + import round-trip ─────────────────────────────────────────────────

TEST_CASE("req: full round-trip save to export to import to load", "[req][req001][req002][req003]") {
    TempDir tmp;
    std::vector<trace::Requirement> original;
    original.push_back({"REQ-RT1", "Round-trip one", "Desc 1", "ISO 26262", "safety"});
    original.push_back({"REQ-RT2", "Round-trip two", "Desc 2", "IEC 61508", "info"});

    // Export to CSV
    auto csv = trace::export_csv(original);
    tmp.write("rt.csv", csv);

    // Import into fresh vector
    std::vector<trace::Requirement> imported;
    auto cnt = trace::import_csv(tmp.path() / "rt.csv", imported);
    REQUIRE(is_ok(cnt));
    REQUIRE(value_of(cnt) == 2);

    // Save to .fusa-reqs.json
    REQUIRE(trace::save_requirements(tmp.path(), imported));

    // Reload from JSON
    auto reloaded = trace::load_requirements(tmp.path());
    REQUIRE(is_ok(reloaded));
    const auto& v = value_of(reloaded);
    REQUIRE(v.size() == 2);
    REQUIRE(v[0].id    == "REQ-RT1");
    REQUIRE(v[1].id    == "REQ-RT2");
    REQUIRE(v[0].title == "Round-trip one");
}
