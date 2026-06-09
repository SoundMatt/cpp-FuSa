#include "badge.hpp"
#include <fstream>
#include <sstream>

namespace cpfusa::badge {

//fusa:req REQ-BADGE001 REQ-BADGE003
Badge from_findings(int errors, int warnings, const std::string& version) {
    Status s = Status::PASS;
    if (errors > 0)   s = Status::FAIL;
    else if (warnings > 0) s = Status::WARN;
    return {s, errors, warnings, version};
}

namespace {

std::pair<std::string,std::string> status_text(const Badge& b) {
    switch (b.status) {
    case Status::FAIL:
        return {"failing (" + std::to_string(b.errors) + " errors)", "#e05d44"};
    case Status::WARN:
        return {"warnings (" + std::to_string(b.warnings) + ")", "#dfb317"};
    default:
        return {"passing", "#4c1"};
    }
}

} // namespace

//fusa:req REQ-BADGE002
std::string render(const Badge& b) {
    auto [msg, color] = status_text(b);
    int lw    = 60;
    int mw    = static_cast<int>(msg.size()) * 7 + 10;
    int total = lw + mw;
    int mx    = lw + mw / 2;
    std::ostringstream ss;
    ss << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << total << "\" height=\"20\">\n"
       << "  <linearGradient id=\"s\" x2=\"0\" y2=\"100%\">\n"
       << "    <stop offset=\"0\" stop-color=\"#bbb\" stop-opacity=\".1\"/>\n"
       << "    <stop offset=\"1\" stop-opacity=\".1\"/>\n"
       << "  </linearGradient>\n"
       << "  <rect rx=\"3\" width=\"" << total << "\" height=\"20\" fill=\"#555\"/>\n"
       << "  <rect rx=\"3\" x=\"" << lw << "\" width=\"" << mw << "\" height=\"20\" fill=\"" << color << "\"/>\n"
       << "  <rect rx=\"3\" width=\"" << total << "\" height=\"20\" fill=\"url(#s)\"/>\n"
       << "  <g fill=\"#fff\" text-anchor=\"middle\" font-family=\"DejaVu Sans,Verdana,Geneva,sans-serif\" font-size=\"11\">\n"
       << "    <text x=\"31\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">cpp-fusa</text>\n"
       << "    <text x=\"31\" y=\"14\">cpp-fusa</text>\n"
       << "    <text x=\"" << mx << "\" y=\"15\" fill=\"#010101\" fill-opacity=\".3\">" << msg << "</text>\n"
       << "    <text x=\"" << mx << "\" y=\"14\">" << msg << "</text>\n"
       << "  </g>\n"
       << "</svg>\n";
    return ss.str();
}

Result<std::monostate> write_badge(const std::filesystem::path& dir, const Badge& b) {
    try {
        std::ofstream out(dir / "fusa-badge.svg");
        out << render(b);
    } catch (const std::exception& e) {
        return std::string("badge: write: ") + e.what();
    }
    return std::monostate{};
}

} // namespace cpfusa::badge
