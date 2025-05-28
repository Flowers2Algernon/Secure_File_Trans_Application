document.addEventListener("DOMContentLoaded", function () {
    // 安全地获取元素
    if (userMenuBtn) {
        const userMenuBtn = document.getElementById("user-menu-btn");}
    const userDropdown = document.getElementById("user-dropdown");
    const notificationBtn = document.getElementById("notification-btn");
    const notificationDropdown = document.getElementById("notification-dropdown");

    // User dropdown toggle - 只有当元素存在时才添加事件
    if (userMenuBtn && userDropdown) {
        userMenuBtn.addEventListener("click", function () {
            userDropdown.classList.toggle("hidden");
            // Hide notification dropdown when user dropdown is shown
            if (notificationDropdown && !notificationDropdown.classList.contains("hidden")) {
                notificationDropdown.classList.add("hidden");
            }
        });
    }

    // Notification dropdown toggle - 只有当元素存在时才添加事件
    if (notificationBtn && notificationDropdown) {
        notificationBtn.addEventListener("click", function () {
            notificationDropdown.classList.toggle("hidden");
            // Hide user dropdown when notification dropdown is shown
            if (userDropdown && !userDropdown.classList.contains("hidden")) {
                userDropdown.classList.add("hidden");
            }
        });
    }

    // Close dropdowns when clicking outside - 添加安全检查
    document.addEventListener("click", function (event) {
        if (userMenuBtn && userDropdown &&
            !userMenuBtn.contains(event.target) &&
            !userDropdown.contains(event.target)) {
            userDropdown.classList.add("hidden");
        }
        
        if (notificationBtn && notificationDropdown &&
            !notificationBtn.contains(event.target) &&
            !notificationDropdown.contains(event.target)) {
            notificationDropdown.classList.add("hidden");
        }
    });
});