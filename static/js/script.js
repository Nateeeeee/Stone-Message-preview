var socket = io();

// Função para adicionar uma mensagem ao chat
function addMessage(message, isUser) {
    var messageDiv = document.createElement('div');
    messageDiv.className = isUser ? 'message user' : 'message server';
    messageDiv.innerHTML = `<strong>${isUser ? 'Você' : message.username}:</strong> ${message.content}`;
    document.getElementById('messages').appendChild(messageDiv);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
}

// Escuta por mensagens do servidor
socket.on('message', function(data) {
    addMessage(data, false); // Mensagem recebida (não é do usuário atual)
});

// Envia mensagem para o servidor
document.getElementById('sendBtn').onclick = function() {
    var message = document.getElementById('myMessage').value;
    if (message) {
        // Exibe a mensagem localmente como "enviada"
        addMessage({ username: 'Você', content: message }, true);

        // Envia a mensagem para o servidor via Socket.IO
        socket.send(message);
        document.getElementById('myMessage').value = '';
    }
};

// Envia mensagem ao pressionar Enter
document.getElementById('myMessage').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        document.getElementById('sendBtn').click();
    }
});

// Mostrar/ocultar o menu dropdown
document.getElementById('menuButton').onclick = function() {
    var dropdown = document.getElementById('menuDropdown');
    if (dropdown.style.display === 'block') {
        dropdown.style.display = 'none';
    } else {
        dropdown.style.display = 'block';
    }
};

// Fechar o menu ao clicar fora dele
window.onclick = function(event) {
    if (!event.target.matches('#menuButton')) {
        var dropdown = document.getElementById('menuDropdown');
        if (dropdown.style.display === 'block') {
            dropdown.style.display = 'none';
        }
    }
};