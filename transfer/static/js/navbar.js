    document.addEventListener("DOMContentLoaded", function () {
// User dropdown toggle
    const userMenuBtn = document.getElementById("user-menu-btn");
    const userDropdown = document.getElementById("user-dropdown");
    userMenuBtn.addEventListener("click", function () {
    userDropdown.classList.toggle("hidden");
    // Hide notification dropdown when user dropdown is shown
    if (!notificationDropdown.classList.contains("hidden")) {
    notificationDropdown.classList.add("hidden");
}
});
    // Notification dropdown toggle
    const notificationBtn = document.getElementById("notification-btn");
    const notificationDropdown = document.getElementById("notification-dropdown");
    notificationBtn.addEventListener("click", function () {
    notificationDropdown.classList.toggle("hidden");
    // Hide user dropdown when notification dropdown is shown
    if (!userDropdown.classList.contains("hidden")) {
    userDropdown.classList.add("hidden");
}
});
    // Close dropdowns when clicking outside
    document.addEventListener("click", function (event) {
    if (
    !userMenuBtn.contains(event.target) &&
    !userDropdown.contains(event.target)
    ) {
    userDropdown.classList.add("hidden");
}
    if (
    !notificationBtn.contains(event.target) &&
    !notificationDropdown.contains(event.target)
    ) {
    notificationDropdown.classList.add("hidden");
}
});

});