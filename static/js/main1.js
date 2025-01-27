document.addEventListener('DOMContentLoaded', function() {
    
    // Attach File button functionality
    var attachBtn = document.getElementById('attach-btn');
    if (attachBtn) {
        attachBtn.addEventListener('click', function() {
            document.getElementById('file-upload').click();
        });
    }

    var fileUpload = document.getElementById('file-upload');
    if (fileUpload) {
        fileUpload.addEventListener('change', function(event) {
            var files = event.target.files;
            var uploadContainer = document.querySelector('.file-upload-container');

            for (var i = 0; i < files.length; i++) {
                var file = files[i];
                var reader = new FileReader();

                reader.onload = (function(file) {
                    return function(event) {
                        var fileType = file.type.split('/')[0];
                        var uploadItem = document.createElement('div');
                        uploadItem.classList.add('file-upload-item');

                        if (fileType === 'image') {
                            var imgPreview = document.createElement('img');
                            imgPreview.src = event.target.result;
                            uploadItem.appendChild(imgPreview);
                        } else if (fileType === 'video') {
                            var videoPreview = document.createElement('video');
                            videoPreview.src = event.target.result;
                            videoPreview.controls = true;
                            uploadItem.appendChild(videoPreview);
                        }

                        var removeButton = document.createElement('button');
                        removeButton.textContent = 'x';
                        removeButton.addEventListener('click', function() {
                            uploadItem.remove();
                        });

                        uploadItem.appendChild(removeButton);
                        uploadContainer.appendChild(uploadItem);
                    };
                })(file);

                reader.readAsDataURL(file);
            }
        });
    }

    // Advertisement rotation logic
    var advertisementImages = [
        "assets/images/banner/advertise.jpg",
        "assets/images/banner/advertise1.jpg"
    ];
    var advertisementIndex = 0;
    var advertisementImage = document.getElementById("advertisement-image");

    function changeAdvertisementImage() {
        advertisementIndex = (advertisementIndex + 1) % advertisementImages.length;
        advertisementImage.src = advertisementImages[advertisementIndex];
    }

    if (advertisementImage) {
        setInterval(changeAdvertisementImage, 5000);
    }

    // Function to toggle between login and create account forms
    // function toggleForm(formId) {
    //     const loginForm = document.getElementById('loginForm');
    //     const createAccountForm = document.getElementById('createAccountForm');
    //     if (formId === 'createAccount') {
    //         loginForm.style.display = 'none';
    //         createAccountForm.style.display = 'block';
    //         window.history.pushState({}, '', '/signup');
    //     } else {
    //         loginForm.style.display = 'block';
    //         createAccountForm.style.display = 'none';
    //         window.history.pushState({}, '', '/login');
    //     }
    // }

    // Ensure the login form is displayed by default on page load
    // const loginForm = document.getElementById('loginForm');
    // const createAccountForm = document.getElementById('createAccountForm');
    // if (loginForm && createAccountForm) {
    //     loginForm.style.display = 'block';
    //     createAccountForm.style.display = 'none';
    // }


    // <!-- JavaScript to make flash messages disappear after 6 seconds -->
        // Auto-hide flash messages after 6 seconds
        setTimeout(() => { 
            document.querySelectorAll('.alert').forEach(alert => alert.style.display = 'none'); 
        }, 4000);

        function redirectToUrl(button) {
            var url = button.getAttribute('data-href');
            location.href = url;
        }

        // When "Save Changes" button is clicked, show the confirmation modal
        $('#saveBtn').click(function() {
            var myModal = new bootstrap.Modal(document.getElementById('confirmModal'));
            myModal.show(); // Show the confirmation modal
        });

        // When "Confirm" button in the modal is clicked, submit the form
        $('#confirmSave').click(function() {
            var myModal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
            myModal.hide(); // Hide the modal

            // Add a hidden input field indicating the action (save)
            $('#account-info-form').append('<input type="hidden" name="action" value="save">');

            // Submit the form
            $('#account-info-form').submit();
        });

        // When "Cancel" button in the modal is clicked, close the modal
        $('#confirmModal .btn-secondary-custom').click(function() {
            var myModal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
            myModal.hide(); // Hide the modal
        });

        // Close the modal if the "X" button (close) is clicked
        $('#confirmModal .close').click(function() {
            var myModal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
            myModal.hide(); // Hide the modal
        });

        // Reset button, reload the page to reset form values
        $('#resetBtn').click(function() {
            location.reload(); // Reload the page to reset form values
        });
});

// <!-- <script>
//         document.addEventListener('DOMContentLoaded', function() {
//             const loginForm = document.getElementById('loginForm');
//             const create_AccountForm = document.getElementById('create_AccountForm');
//             const reset_accountForm = document.getElementById('reset_accountForm');

//             // Function to toggle between login, create account, and reset password forms
//             function toggleForm(formId) {
//                 loginForm.style.display = 'none';
//                 create_AccountForm.style.display = 'none';
//                 reset_accountForm.style.display = 'none';

//                 if (formId === 'create_Account') {
//                     create_AccountForm.style.display = 'block';
//                     window.history.pushState({}, '', '/sign_up');
//                 } else if (formId === 'reset_account') {
//                     reset_accountForm.style.display = 'block';
//                     window.history.pushState({}, '', '/reset_account');
//                 } else {
//                     loginForm.style.display = 'block';
//                     window.history.pushState({}, '', '/login');
//                 }
//             }

//             // Initial display
//             const path = window.location.pathname;
//             if (path === '/sign_up') {
//                 toggleForm('create_Account');
//             } else if (path === '/reset_account') {
//                 toggleForm('reset_account');
//             } else {
//                 toggleForm('login');
//             }

//             // Expose the function to global scope so it can be called from HTML
//             window.toggleForm = toggleForm;
//         });
//     </script> -->

//     <!-- Include your JavaScript for form toggling -->
//     <!-- <script>
//         document.addEventListener('DOMContentLoaded', function() {
//             const loginForm = document.getElementById('loginForm');
//             const create_AccountForm = document.getElementById('create_AccountForm');
//             const reset_accountForm = document.getElementById('reset_accountForm');
    
//             // Function to toggle between login, create account, and reset password forms
//             function toggleForm(formId) {
//                 loginForm.style.display = 'none';
//                 create_AccountForm.style.display = 'none';
//                 reset_accountForm.style.display = 'none';
    
//                 if (formId === 'create_Account') {
//                     create_AccountForm.style.display = 'block';
//                 } else if (formId === 'reset_account') {
//                     reset_accountForm.style.display = 'block';
//                 } else {
//                     loginForm.style.display = 'block';
//                 }
//             }
    
//             // Get the form type passed from Flask
//             const formType = "{{ form_type }}";  // This will be either 'login', 'sign_up', or 'reset_account'
//             toggleForm(formType);
    
//             // Expose the function to global scope so it can be called from HTML
//             window.toggleForm = toggleForm;
//         });
//     </script>
    