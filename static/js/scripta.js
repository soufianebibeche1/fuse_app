// Hndle click 
function handleInboxClick() {
    // Redirect to the /inbox route
    window.location.href = '/inbox';
}

function navigateToNotifications() {
    // Redirect to the /view_notifications route
    window.location.href = '/user/view_notifications';
    // window.location.href = "{{ url_for('user.view_notifications') }}";
}

function redirectToAccount() {
    // window.location.href = "{{ url_for('user.account') }}";
    window.location.href = '/user/account'
}