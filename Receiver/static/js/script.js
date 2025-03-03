document.addEventListener("DOMContentLoaded", () => {
    let audio = document.getElementById("audioPlayerrecv");
    audio.src = "static/assets/audio/decrypted_audio.mp3"; // Set the latest file
    audio.load(); // Ensure it reloads
});
