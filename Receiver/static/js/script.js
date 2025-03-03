document.addEventListener("DOMContentLoaded", () => {
    let audio = document.getElementById("audioPlayerrecv");
    audio.src = "static/assets/audio/decrypted_audio.mp3"; // Set the latest file
    audio.load(); // Ensure it reloads
});

document.addEventListener("DOMContentLoaded", function () {
    var digest1 = document.getElementById("digest_value1").value;
    var digest2 = document.getElementById("digest_value2").value;
    var authenDiv = document.querySelector(".authen");

    if ((digest1 == digest2) && (digest2 == "No connection yet")) {
        authenDiv.style.backgroundColor = "white";
        authenDiv.innerHTML = "Not Received";
    }
    else if ((digest1 == digest2) && (digest2 != "No connection yet")) {
        authenDiv.style.backgroundColor = "lightgreen";
        authenDiv.innerHTML = "Verified";
    } else {
        authenDiv.style.backgroundColor = "red";
        authenDiv.innerHTML = "Tampered";
    }
});

