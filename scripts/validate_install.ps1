<#
.SYNOPSIS
  Validates the installed Loop Guard CMake package with an independent consumer.

.DESCRIPTION
  Builds the project, installs it into a prefix, generates a small consumer project
  OUTSIDE the source tree that uses find_package(LoopGuard CONFIG REQUIRED), builds and
  runs it against the installed prefix, and then runs the installed tools.

  Every step fails loudly. The only thing written inside the source tree is the build
  directory.

.PARAMETER BuildDir
  Build directory to use. Defaults to <repo>/build.

.PARAMETER Prefix
  Install prefix. Defaults to a directory outside the source tree.
#>
[CmdletBinding()]
param(
  [string]$BuildDir,
  [string]$Prefix,
  [string]$Config = 'Release'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $BuildDir) { $BuildDir = Join-Path $repo 'build' }
if (-not $Prefix) { $Prefix = Join-Path ([System.IO.Path]::GetTempPath()) 'loop-guard-prefix' }
$helper = Join-Path $PSScriptRoot 'with-msvc.ps1'

function Invoke-Msvc {
  param([string]$Label, [string]$Command, [string]$WorkDir)
  Write-Host "== $Label"
  & pwsh -NoProfile -File $helper -Quiet -Command $Command -WorkDir $WorkDir
  if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE" }
}

Invoke-Msvc 'configure' ('cmake -S . -B "' + $BuildDir + '" -G Ninja -DCMAKE_BUILD_TYPE=' + $Config) $repo
Invoke-Msvc 'build' ('cmake --build "' + $BuildDir + '" --parallel') $repo
Invoke-Msvc 'install' ('cmake --install "' + $BuildDir + '" --prefix "' + $Prefix + '"') $repo

# The consumer lives outside the source tree on purpose: nothing about it may depend on
# the repository layout or on the build tree.
$consumerRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('loop-guard-consumer-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $consumerRoot -Force | Out-Null
Write-Host "== consumer at $consumerRoot"

$consumerSource = @'
#include <iostream>
#include <string>

#include "loop_guard/containment.hpp"
#include "loop_guard/detect.hpp"
#include "loop_guard/evidence.hpp"
#include "loop_guard/topology.hpp"
#include "loop_guard/version.hpp"

using namespace loop_guard;

int main() {
  TopologyBuilder builder;
  builder.set_generation(TopologyGeneration::from_value(1));
  TrafficSelector selector;
  selector.id = TrafficSelectorId::from_value(1);
  if (!builder.add_selector(selector).is_ok()) {
    return 1;
  }
  for (std::uint64_t id = 1; id <= 3; ++id) {
    ResourceRecord record;
    record.id = ResourceId::from_value(id);
    record.domain = DomainId::from_value(1);
    record.kind = ResourceKind::Switch;
    record.admin = AdministrativeState::Enabled;
    record.containable = true;
    record.containment_cost = 1;
    if (!builder.add_resource(record).is_ok()) {
      return 1;
    }
  }
  for (std::uint64_t id = 1; id <= 3; ++id) {
    ForwardingEdge edge;
    edge.id = ForwardingEdgeId::from_value(id);
    edge.from = ResourceId::from_value(id);
    edge.to = ResourceId::from_value((id % 3U) + 1U);
    edge.domain = DomainId::from_value(1);
    edge.link = LinkState::Up;
    edge.admitted_selectors = {TrafficSelectorId::from_value(1)};
    if (!builder.add_edge(edge).is_ok()) {
      return 1;
    }
  }
  auto topology = builder.build();
  if (!topology.has_value()) {
    return 1;
  }

  FenceVector fence;
  fence.topology = TopologyGeneration::from_value(1);
  fence.forwarding = ForwardingGeneration::from_value(1);
  fence.policy = PolicyGeneration::from_value(1);
  fence.fabric_epoch = FabricEpoch::from_value(1);
  fence.epoch = CoordinatorEpoch::from_value(1);
  fence.boot = BootId::from_value(1);

  EvidenceLedger ledger;
  for (const ForwardingEdge& edge : topology.value().edges()) {
    ForwardingObservation observation;
    observation.id = ObservationId::from_value(edge.id.value());
    observation.edge = edge.id;
    observation.from = edge.from;
    observation.to = edge.to;
    observation.domain = edge.domain;
    observation.klass = EvidenceClass::Present;
    observation.selectors = edge.admitted_selectors;
    observation.topology_generation = fence.topology;
    observation.forwarding_generation = fence.forwarding;
    observation.producer = ProducerId::from_value(1);
    observation.sequence = ProducerSequence::from_value(edge.id.value());
    observation.lease.boot = fence.boot;
    observation.lease.epoch = fence.epoch;
    observation.lease.fabric_epoch = fence.fabric_epoch;
    observation.lease.valid_until = 1000;
    if (!ledger.submit(observation).is_ok()) {
      return 1;
    }
  }

  DetectionRequest request;
  request.topology = &topology.value();
  request.ledger = &ledger;
  request.fence = fence;
  request.now = 100;
  const LoopDetector detector;
  const auto assessment = detector.assess(request);
  if (!assessment.has_value()) {
    return 1;
  }
  std::cout << "version=" << version_string() << " outcome=" << to_string(assessment.value().outcome)
            << " witnesses=" << assessment.value().witnesses.size() << "\n";
  if (assessment.value().outcome != LoopOutcome::LoopConfirmed) {
    return 2;
  }

  ContainmentPolicy policy;
  policy.generation = fence.policy;
  policy.max_targets = 4;
  policy.max_total_cost = 16;
  policy.eligible_kinds = {ResourceKind::Switch};
  const ContainmentPlanner planner;
  const auto plan = planner.plan(assessment.value(), topology.value(), policy, 100);
  if (!plan.has_value() || !plan.value().authorizes_action()) {
    return 3;
  }
  std::cout << "plan_outcome=" << to_string(plan.value().outcome)
            << " targets=" << plan.value().targets.size() << "\n";
  return 0;
}
'@
Set-Content -Path (Join-Path $consumerRoot 'main.cpp') -Value $consumerSource -Encoding UTF8

$consumerCmake = @"
cmake_minimum_required(VERSION 3.24)
project(LoopGuardConsumer LANGUAGES CXX)
find_package(LoopGuard 1.0 CONFIG REQUIRED)
add_executable(consumer main.cpp)
target_compile_features(consumer PRIVATE cxx_std_20)
set_target_properties(consumer PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(consumer PRIVATE /W4 /WX /permissive- /utf-8)
else()
  target_compile_options(consumer PRIVATE -Wall -Wextra -Werror)
endif()
target_link_libraries(consumer PRIVATE SummonSoftwareLabs::LoopGuard)
"@
Set-Content -Path (Join-Path $consumerRoot 'CMakeLists.txt') -Value $consumerCmake -Encoding UTF8

Invoke-Msvc 'consumer configure' ('cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=' + $Config + ' -DCMAKE_PREFIX_PATH="' + $Prefix + '"') $consumerRoot
Invoke-Msvc 'consumer build' 'cmake --build build --parallel' $consumerRoot
Invoke-Msvc 'consumer run' 'build\consumer.exe' $consumerRoot

Write-Host '== installed tools'
$installedTools = @(
  (Join-Path $Prefix 'bin\lg_coordinator.exe'),
  (Join-Path $Prefix 'bin\lg_worker.exe'),
  (Join-Path $Prefix 'bin\lgctl.exe'))
foreach ($tool in $installedTools) {
  if (-not (Test-Path -LiteralPath $tool)) { throw "installed tool is missing: $tool" }
  & $tool --help | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "installed tool failed: $tool (exit $LASTEXITCODE)" }
  Write-Host "   ran $tool"
}

Write-Host ''
Write-Host "install validation succeeded: prefix=$Prefix consumer=$consumerRoot"
