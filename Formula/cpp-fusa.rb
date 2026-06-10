class CppFusa < Formula
  desc "C++ Functional Safety Enablement Toolkit"
  homepage "https://github.com/SoundMatt/cpp-FuSa"
  url "https://github.com/SoundMatt/cpp-FuSa/archive/refs/tags/v0.7.0.tar.gz"
  # sha256 is computed automatically by `brew audit --new-formula` after the tag is published.
  # Run: brew fetch --build-from-source Formula/cpp-fusa.rb
  sha256 :no_check
  license "MPL-2.0"
  head "https://github.com/SoundMatt/cpp-FuSa.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "ninja" => :build

  def install
    system "cmake", "-B", "build", "-G", "Ninja",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DCPFUSA_BUILD_TESTS=OFF",
                    *std_cmake_args
    system "cmake", "--build", "build", "--parallel"
    system "cmake", "--install", "build"
  end

  test do
    assert_match "cpp-FuSa 0.7.0", shell_output("#{bin}/cpfusa version")
    (testpath / ".fusa.json").write({
      "configVersion" => "1.0",
      "project" => {"name" => "brew-test", "version" => "1.0.0"},
      "standard" => "iso26262",
      "asil" => "ASIL-B"
    }.to_json)
    assert_match "FUSA00", shell_output("#{bin}/cpfusa check", 1)
  end
end
