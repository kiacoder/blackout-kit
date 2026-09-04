class BlackoutKit < Formula
  desc "🛡️ Local network coordination toolkit for proxy/VPN engines"
  homepage "https://github.com/kiacoder/blackout-kit"
  version "1.1.1"
  
  url "https://github.com/kiacoder/blackout-kit/releases/download/v#{version}/blackout.exe", only_if: :windows
  sha256 "b4d8e4c3f2c0a1e5d7f9a8c2e4f6h8j0k2m4n6p8q0s2t4v6w8y0a2b4c6d8e0" if OS.windows?
  
  if OS.linux?
    url "https://github.com/kiacoder/blackout-kit/releases/download/v#{version}/blackout-engine-linux-amd64"
    sha256 "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1"
  end

  def install
    if OS.windows?
      bin.install "blackout.exe"
    else
      bin.install "blackout-engine-linux-amd64" => "blackout"
    end
  end

  def post_install
    unless File.exist?("#{ENV['HOME']}/.blackout-kit")
      system "mkdir", "-p", "#{ENV['HOME']}/.blackout-kit"
    end
  end

  def caveats
    <<~EOS
      Blackout Kit is ready to use!
      Get started: blackout setup
    EOS
  end

  test do
    system "#{bin}/blackout", "--version"
  end
end
