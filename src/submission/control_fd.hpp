#pragma once
namespace turtle::submission {
// Reserved only between the controller and its two role executables.
// The submitted implementation retains ordinary stdin/stdout/stderr.
inline constexpr int role_control_fd = 3;
}
