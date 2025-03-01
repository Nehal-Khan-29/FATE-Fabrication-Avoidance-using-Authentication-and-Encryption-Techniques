/*<!-- ---------------------------------------------------- Send ---------------------------------------------------- -->*/

const fileInput = document.getElementById('audioFile');
const audioPlayer = document.getElementById('audioPlayer');

fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    if (file) {
        const fileURL = URL.createObjectURL(file);
        audioPlayer.src = fileURL;
    } else {
        alert("No file chosen!");
    }
});

/*
function getLocalIP(callback) {
    const peerConnection = new RTCPeerConnection({ iceServers: [] });
    peerConnection.createDataChannel('');
    
    peerConnection.createOffer().then(offer => peerConnection.setLocalDescription(offer));
    
    peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
            const ipMatch = event.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3})/);
            if (ipMatch) {
                callback(ipMatch[1]);
                peerConnection.close();
            }
        }
    };
}

getLocalIP(function(ip) {
    document.querySelector('.ip1').textContent = `${ip}`;
});
*/