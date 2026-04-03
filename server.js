const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');

const app = express();

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

  await fetch('https://exp.host/--/api/v2/push/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(mensagens)
  });
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

    res.json(usuario);

  } catch (err) {
    console.log('💥 ERRO LOGIN:', err);
    res.status(500).json({ erro: err.message });
  }
});

// =========================
// 👤 USUÁRIOS
// =========================

// LISTAR
app.get('/usuarios', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM usuarios');
    res.json(rows);
  } catch (err) {
    console.log('💥 ERRO USUARIOS:', err);
    res.status(500).json({ erro: err.message });
  }
});

// CRIAR
app.post('/usuarios', async (req, res) => {
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

app.post('/usuarios/token', async (req, res) => {
  try {
    const { usuario, token } = req.body;

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
app.put('/usuarios/alterar-senha', async (req, res) => {
  try {
    const { nome, senhaAtual, novaSenha } = req.body;

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
app.delete('/usuarios/:id', async (req, res) => {
  try {
    const { id } = req.params;

    console.log('🗑️ DELETANDO USUARIO:', id);

    await db.query('DELETE FROM usuarios WHERE id = ?', [id]);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO DELETE:', err);
    res.status(500).json({ erro: err.message });
  }
});


// editar usuarios

// EDITAR USUÁRIO
app.put('/usuarios/:id', async (req, res) => {
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
app.get('/chamados', async (req, res) => {
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
app.post('/chamados', async (req, res) => {
  try {
    const {
      titulo, descricao, loja, setor,
      status, usuario, departamento, fotos, sn
    } = req.body;

    const fotosJSON = JSON.stringify(fotos || []);

    const [result] = await db.query(`
      INSERT INTO chamados
      (titulo, descricao, loja, setor, status, criadoPor, departamento, fotos, sn, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      titulo, descricao, loja, setor,
      status, usuario, departamento, fotosJSON, sn || null
    ]);

    const chamadoCriado = {
      id: result.insertId,
      titulo,
      loja
    };

    const [users] = await db.query(
      "SELECT token FROM usuarios WHERE departamento = 'manutencao' AND token IS NOT NULL"
    );

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


app.delete('/chamados/:id', async (req, res) => {
  try {
    const { id } = req.params;

    await db.query('DELETE FROM chamados WHERE id = ?', [id]);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO DELETE CHAMADO:', err);
    res.status(500).json({ erro: err.message });
  }
});






// ATUALIZAR STATUS DO CHAMADO
app.put('/chamados/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, usuario } = req.body;

    console.log('🔥 UPDATE CHAMADO');
    console.log('📥 ID:', id);
    console.log('📥 STATUS:', status);
    console.log('📥 USUARIO:', usuario);

    let sql = `UPDATE chamados SET status = ?`;
    let valores = [status];

    // 🔥 ASSUMIR
    if (status && status.trim().toUpperCase() === 'ANDAMENTO') {
      sql += `, assumidoPor = ?, dataAssumido = NOW()`;
      valores.push(usuario);
    }

    // 🔥 FINALIZAR
    if (status && status.trim().toUpperCase() === 'FINALIZADO') {
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