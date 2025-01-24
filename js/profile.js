  // Function to open file input when the profile icon is clicked
  function triggerFileInput() {
    document.getElementById('fileInput').click();
}

// Function to update the profile image when a new photo is selected
function updateProfileImage(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const profileIcon = document.querySelector('.profile-icon');
            profileIcon.style.backgroundImage = `url(${e.target.result})`;
            const icon = document.querySelector('.profile-icon i');
            icon.style.display = 'none'; // Hide the icon
        };
        reader.readAsDataURL(file);
    }
}

// Function to make name editable when the user clicks the edit button
function editName() {
    const userName = document.getElementById('userName');
    const editNameBtn = document.getElementById('editNameBtn');
    if (userName.contentEditable === "true") {
        userName.contentEditable = "false";
        editNameBtn.textContent = "";
    } else {
        userName.contentEditable = "true";
        userName.focus();
        editNameBtn.textContent = "";
    }
}

// Function to save the profile data
function saveProfile() {
    const updatedProfile = {
        name: document.getElementById('userName').textContent,
        firstname:document.getElementById('firstname').value,
        lastname:document.getElementById('lastname').value,
        phone: document.getElementById('phone').value,
        email: document.getElementById('email').value,
        gender: document.getElementById('gender').value,
        address: document.getElementById('address').value,
        dob: document.getElementById('dob').value,
        age: document.getElementById('age').value
    };
    console.log("Profile saved:", updatedProfile);
}
