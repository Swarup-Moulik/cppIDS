$ErrorActionPreference = "Stop"

if (-not (Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
}

cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
ninja

Write-Host "Build complete. Executable located at ./build/cppids.exe" -ForegroundColor Green
cd ..
