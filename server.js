const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')

const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();

const rateLimit = require('express-rate-limit');

// 🔒 proteção global (opcional)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});

// 🔥 proteção no login 
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { erro: 'Muitas tentativas, tente novamente mais tarde' }
});

app.use('/login', loginLimiter);


console.log('🔥 NOVO DEPLOY ATIVO');

// 🔥 CAPTURA ERROS
process.on('uncaughtException', (err) => {
  console.log('💥 ERRO NÃO TRATADO:', err);
});

process.on('unhandledRejection', (err) => {
  console.log('💥 PROMISE ERROR:', err);
});

app.use(express.json({ limit: '50mb' }));
app.use(cors());
app.use(limiter);


// =========================
// 🔥 MYSQL (PADRÃO PROMISE)
// =========================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: { rejectUnauthorized: false }
}).promise();

// 🔥 TESTE CONEXÃO
(async () => {
  try {
    await db.query('SELECT 1');
    console.log('✅ MYSQL CONECTADO');
  } catch (err) {
    console.log('❌ ERRO MYSQL:', err);
  }
})();

// =========================
// 🔔 NOTIFICAÇÃO
// =========================
async function enviarNotificacao(tokens, chamado) {
  const mensagens = tokens.map(token => ({
    to: token,
    sound: 'default',
    title: '🔧 Novo chamado',
    body: `${chamado.titulo} - ${chamado.loja}`,
    data: { id: chamado.id }
  }));

  console.log('🚀 ENVIANDO:', mensagens);

  const response = await fetch('https://exp.host/--/api/v2/push/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mensagens)
  });

  const data = await response.json();

  console.log('📬 RESPOSTA EXPO:', data);
}

// =========================
// 🔐 LOGIN
// =========================
app.post('/login', async (req, res) => {
  try {
    const { nome, senha } = req.body;

    const [rows] = await db.query(
      'SELECT * FROM usuarios WHERE nome = ?',
      [nome]
    );

    if (rows.length === 0) {
      return res.status(401).json({ erro: 'Usuário inválido' });
    }

    const usuario = rows[0];

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(401).json({ erro: 'Senha inválida' });
    }

    // 🔒 REMOVE SENHA DO OBJETO
    delete usuario.senha;

    // 🔥 CRIA TOKEN
    const token = jwt.sign(
      {
        id: usuario.id,
        nome: usuario.nome,
        nivel: usuario.nivel,
        departamento: usuario.departamento
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ usuario, token });

  } catch (err) {
    console.log('💥 ERRO LOGIN:', err);
    res.status(500).json({ erro: err.message });
  }
});

function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ erro: 'Token não enviado' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ erro: 'Token inválido' });
  }
}



// =========================
// 👤 USUÁRIOS
// =========================

// LISTAR
app.get('/usuarios', auth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM usuarios');
    res.json(rows);
  } catch (err) {
    console.log('💥 ERRO USUARIOS:', err);
    res.status(500).json({ erro: err.message });
  }
});

// CRIAR
app.post('/usuarios', auth, async (req, res) => {

  if (req.user.nivel !== 'adm') {
  return res.status(403).json({ erro: 'Sem permissão' });
}

  try {
    const { nome, senha, nivel, departamento, loja } = req.body;

    const senhaHash = await bcrypt.hash(senha, 10);

    await db.query(
      `INSERT INTO usuarios (nome, senha, nivel, departamento, loja)
       VALUES (?, ?, ?, ?, ?)`,
      [nome, senhaHash, nivel, departamento, loja]
    );

    res.json({ sucesso: true });

  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ erro: 'Usuário já existe' });
    }

    console.log('💥 ERRO CRIAR USUARIO:', err);
    res.status(500).json({ erro: err.message });
  }
});


// token

app.post('/usuarios/token', auth, async (req, res) => {
  try {
    const { token } = req.body;
    const usuario = req.user.nome;

    await db.query(
      'UPDATE usuarios SET token = ? WHERE nome = ?',
      [token, usuario]
    );

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO TOKEN:', err);
    res.status(500).json({ erro: err.message });
  }
});





// ALTERAR SENHA
app.put('/usuarios/alterar-senha', auth, async (req, res) => {
  try {
    const { senhaAtual, novaSenha } = req.body;
    const nome = req.user.nome;

    const [rows] = await db.query(
      'SELECT * FROM usuarios WHERE nome = ?',
      [nome]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    }

    const usuario = rows[0];

    const senhaValida = await bcrypt.compare(senhaAtual, usuario.senha);

    if (!senhaValida) {
      return res.status(400).json({ erro: 'Senha atual incorreta' });
    }

    const novaSenhaHash = await bcrypt.hash(novaSenha, 10);

    await db.query(
      'UPDATE usuarios SET senha = ? WHERE nome = ?',
      [novaSenhaHash, nome]
    );

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO ALTERAR SENHA:', err);
    res.status(500).json({ erro: err.message });
  }
});


// deletar usuario
app.delete('/usuarios/:id', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    // 🔥 evitar auto-delete
    if (Number(req.user.id) === Number(id)) {
      return res.status(400).json({ erro: 'Você não pode deletar seu próprio usuário' });
    }

    // 🔥 verificar se existe
    const [rows] = await db.query(
      'SELECT id FROM usuarios WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    }

    // 🔥 deletar
    await db.query('DELETE FROM usuarios WHERE id = ?', [id]);

    console.log('🗑️ USUARIO DELETADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO DELETE:', err);
    res.status(500).json({ erro: err.message });
  }
});
// editar usuarios

// EDITAR USUÁRIO
app.put('/usuarios/:id', auth, async (req, res) => {

  if (req.user.nivel !== 'adm') {
  return res.status(403).json({ erro: 'Sem permissão' });
}

  try {
    const { id } = req.params;
    const { senha, nivel, departamento, loja } = req.body;

    let campos = [];
    let valores = [];

    // 🔐 senha (se vier)
    if (senha) {
      const hash = await bcrypt.hash(senha, 10);
      campos.push('senha = ?');
      valores.push(hash);
    }

    if (nivel) {
      campos.push('nivel = ?');
      valores.push(nivel);
    }

    if (departamento) {
      campos.push('departamento = ?');
      valores.push(departamento);
    }

    if (loja !== undefined) {
      campos.push('loja = ?');
      valores.push(loja);
    }

    if (campos.length === 0) {
      return res.status(400).json({ erro: 'Nada para atualizar' });
    }

    const sql = `
      UPDATE usuarios 
      SET ${campos.join(', ')}
      WHERE id = ?
    `;

    valores.push(id);

    await db.query(sql, valores);

    console.log('✏️ USUARIO EDITADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO EDITAR:', err);
    res.status(500).json({ erro: err.message });
  }
});



// =========================
// 📄 CHAMADOS
// =========================

// LISTAR
app.get('/chamados', auth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM chamados');

    const chamados = rows.map(c => ({
      ...c,
      fotos: (() => {
        try { return JSON.parse(c.fotos); }
        catch { return []; }
      })()
    }));

    res.json(chamados);

  } catch (err) {
    console.log('💥 ERRO CHAMADOS:', err);
    res.status(500).json({ erro: err.message });
  }
});

// CRIAR
app.post('/chamados', auth, async (req, res) => {
  try {
    const {
      titulo, descricao, loja, setor,
      status, fotos, sn
    } = req.body;

    // 🔒 dados confiáveis vêm do token
    const usuario = req.user.nome;
    const departamento = req.user.departamento;

    const fotosJSON = JSON.stringify(fotos || []);

    const [result] = await db.query(`
      INSERT INTO chamados
      (titulo, descricao, loja, setor, status, criadoPor, departamento, fotos, sn, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      titulo,
      descricao,
      loja,
      setor,
      status,
      usuario,
      departamento,
      fotosJSON,
      sn || null
    ]);

    const chamadoCriado = {
      id: result.insertId,
      titulo,
      loja
    };

    const [users] = await db.query(`
      SELECT token FROM usuarios 
      WHERE LOWER(TRIM(departamento)) = 'manutencao'
      AND token IS NOT NULL
      AND token != ''
    `);

    console.log('📱 TOKENS ENCONTRADOS:', users);

    if (users.length > 0) {
      const tokens = users.map(u => u.token);
      enviarNotificacao(tokens, chamadoCriado);
    }

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO CHAMADO:', err);
    res.status(500).json({ erro: err.message });
  }
});


// excluir chamados


app.delete('/chamados/:id', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    // 🔍 verifica se existe
    const [rows] = await db.query(
      'SELECT id FROM chamados WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Chamado não encontrado' });
    }

    // 🗑️ deleta
    await db.query('DELETE FROM chamados WHERE id = ?', [id]);

    console.log('🗑️ CHAMADO DELETADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO DELETE CHAMADO:', err);
    res.status(500).json({ erro: err.message });
  }
});





// ATUALIZAR STATUS DO CHAMADO
app.put('/chamados/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const usuario = req.user.nome;

    if (!status) {
      return res.status(400).json({ erro: 'Status é obrigatório' });
    }

    console.log('🔥 UPDATE CHAMADO');
    console.log('📥 ID:', id);
    console.log('📥 STATUS:', status);
    console.log('📥 USUARIO:', usuario);

    // 🔍 verifica se chamado existe
  const [existe] = await db.query(
  'SELECT id, status, assumidoPor FROM chamados WHERE id = ?',
  [id]
);

    if (existe.length === 0) {
      return res.status(404).json({ erro: 'Chamado não encontrado' });
    }

    let sql = `UPDATE chamados SET status = ?`;
    let valores = [status];

    // 🔥 ASSUMIR
    if (status.trim().toUpperCase() === 'ANDAMENTO') {

      const [rows] = await db.query(
        `SELECT COUNT(*) as total 
         FROM chamados 
         WHERE assumidoPor = ? 
         AND status = 'ANDAMENTO'
         AND id != ?`,
        [usuario, id]
      );

      const total = rows[0].total;

      console.log('📊 Chamados em andamento:', total);

      if (total >= 5) {
        return res.status(400).json({
          erro: 'Você já atingiu o limite de 5 chamados em andamento'
        });
      }

      sql += `, assumidoPor = ?, dataAssumido = NOW()`;
      valores.push(usuario);
    }

    // 🔥 FINALIZAR
    if (status.trim().toUpperCase() === 'FINALIZADO') {

      const chamado = existe[0];

      if (
        chamado.assumidoPor &&
        chamado.assumidoPor !== usuario &&
        req.user.nivel !== 'adm'
      ) {
        return res.status(403).json({
          erro: 'Apenas quem assumiu ou um administrador pode finalizar este chamado'
        });
      }

      sql += `, finalizadoPor = ?, dataFinalizacao = NOW()`;
      valores.push(usuario);
    }

    sql += ` WHERE id = ?`;
    valores.push(id);

    await db.query(sql, valores);

    console.log('✅ CHAMADO ATUALIZADO');

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO UPDATE:', err);
    res.status(500).json({ erro: err.message });
  }
});





// =========================
// 🚀 SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});