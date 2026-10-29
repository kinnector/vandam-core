#include "kinnector/ipc.h"
#include "platform.h"
#include <memory>

#include "linux/linux_ipc.h"

namespace kinnector::ipc {

std::unique_ptr<ITelemetrySender> CreateTelemetrySender() {
    return std::make_unique<lnx::LinuxTelemetrySender>();
}

} // namespace kinnector::ipc
