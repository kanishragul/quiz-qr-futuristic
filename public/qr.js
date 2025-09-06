const qrContainer = document.getElementById('qr');
const joinUrl = window.location.origin + '/participant.html';

new QRCode(qrContainer, {
  text: joinUrl,
  width: 220,
  height: 220,
  colorDark: '#000000ff',
  colorLight: '#ffffffff',
  correctLevel: QRCode.CorrectLevel.H
});
