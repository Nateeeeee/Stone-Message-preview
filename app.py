from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_socketio import SocketIO, send
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    registration_code = db.Column(db.String(10), nullable=True)  # Código de registro

# Modelo de Mensagem
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Cria o banco de dados e o usuário admin (execute apenas uma vez)
with app.app_context():
    db.create_all()

    # Verifica se o usuário admin já existe
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        # Cria o usuário admin
        hashed_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        admin_user = User(username='admin', password=hashed_password, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        print('Usuário admin criado com sucesso!')

# Função para criptografar a senha
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Função para verificar a senha
def check_password(password, hashed_password):
    if not hashed_password.startswith('$2b$'):
        return False
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Rota principal (chat)
@app.route('/')
def index():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        is_admin = user.is_admin if user else False

        # Recupera as últimas 50 mensagens do banco de dados
        messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
        messages = list(reversed(messages))  # Ordena do mais antigo para o mais recente

        return render_template('index.html', username=session['username'], is_admin=is_admin, messages=messages)
    return redirect(url_for('login'))

# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password(password, user.password):
            session['username'] = username
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        flash('Usuário ou senha inválidos', 'error')
    return render_template('login.html')

# Rota de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        registration_code = request.form['registration_code']

        # Verifica se o código de registro é válido
        admin_user = User.query.filter_by(is_admin=True).first()
        if not admin_user or registration_code != admin_user.registration_code:
            flash('Código de registro inválido.', 'error')
            return redirect(url_for('register'))

        if not username or not password or not confirm_password:
            flash('Todos os campos são obrigatórios.', 'error')
        elif password != confirm_password:
            flash('As senhas não coincidem.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.', 'error')
        else:
            hashed_password = hash_password(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

# Rota de logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Você foi desconectado.', 'success')
    return redirect(url_for('login'))

# Rota de mudança de senha
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = User.query.filter_by(username=session['username']).first()
        if not user or not check_password(current_password, user.password):
            flash('Senha atual incorreta.', 'error')
        elif new_password != confirm_password:
            flash('As novas senhas não coincidem.', 'error')
        else:
            user.password = hash_password(new_password)
            db.session.commit()
            flash('Senha alterada com sucesso!', 'success')
            return redirect(url_for('index'))
    return render_template('change_password.html')

# Rota do painel de admin
@app.route('/admin')
def admin_panel():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Verifica se o usuário é admin
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_admin:
        flash('Acesso negado. Você não é um administrador.', 'error')
        return redirect(url_for('index'))

    # Lista todos os usuários
    users = User.query.all()
    return render_template('admin.html', users=users)

# Rota para gerar código de registro
@app.route('/admin/generate_code', methods=['POST'])
def generate_code():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Verifica se o usuário é admin
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_admin:
        flash('Acesso negado. Você não é um administrador.', 'error')
        return redirect(url_for('index'))

    # Gera um código de registro aleatório
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

    # Salva o código no banco de dados
    user.registration_code = code
    db.session.commit()

    flash(f'Código de registro gerado: {code}', 'success')
    return redirect(url_for('admin_panel'))

# Rota para editar usuário
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Verifica se o usuário é admin
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_admin:
        flash('Acesso negado. Você não é um administrador.', 'error')
        return redirect(url_for('index'))

    # Busca o usuário a ser editado
    user_to_edit = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form['username']
        is_admin = request.form.get('is_admin') == 'on'

        user_to_edit.username = username
        user_to_edit.is_admin = is_admin
        db.session.commit()
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('admin_panel'))

    return render_template('edit_user.html', user=user_to_edit)

# Rota para excluir usuário
@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    # Verifica se o usuário é admin
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_admin:
        flash('Acesso negado. Você não é um administrador.', 'error')
        return redirect(url_for('index'))

    # Busca o usuário a ser excluído
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('Usuário excluído com sucesso!', 'success')
    return redirect(url_for('admin_panel'))

# SocketIO: Recebe e retransmite mensagens
@socketio.on('message')
def handleMessage(msg):
    username = session.get('username', 'Anônimo')
    
    # Salva a mensagem no banco de dados
    new_message = Message(content=msg, username=username)
    db.session.add(new_message)
    db.session.commit()

    # Envia a mensagem para todos os clientes, exceto o remetente
    send({'username': username, 'content': msg}, broadcast=True, include_self=False)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)