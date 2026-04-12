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
    departamento: usuario.departamento,
    loja: usuario.loja // 🔥 AQUI!
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

// LISTAR USUARIOS
app.get('/usuarios', auth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM usuarios');
    res.json(rows);
  } catch (err) {
    console.log('💥 ERRO USUARIOS:', err);
    res.status(500).json({ erro: err.message });
  }
});

// CRIAR USUARIOS
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
      'UPDATE usuarios SET push_token = ? WHERE nome = ?',
      [token, usuario]
    );

    res.json({ sucesso: true });

  } catch (err) {
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

// LISTAR CHAMDOS
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

// CRIAR CHAMADOS
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


// CRIAR LOJAS E SETORES


app.get('/lojas', auth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM lojas');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});


app.get('/setores', auth, async (req, res) => {
  const [rows] = await db.query('SELECT * FROM setores');
  res.json(rows);
});



// CRIAR SOMENTE ADM

app.post('/lojas', auth, async (req, res) => {
  if (req.user.nivel !== 'adm') {
    return res.status(403).json({ erro: 'Sem permissão' });
  }

  const { nome } = req.body;

  await db.query('INSERT INTO lojas (nome) VALUES (?)', [nome]);

  res.json({ sucesso: true });
});



// CRIAR SETORES

app.post('/setores', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { nome } = req.body;

    if (!nome) {
      return res.status(400).json({ erro: 'Nome obrigatório' });
    }

    await db.query(
      'INSERT INTO setores (nome) VALUES (?)',
      [nome]
    );

    res.json({ sucesso: true });

  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ erro: 'Setor já existe' });
    }

    res.status(500).json({ erro: err.message });
  }
});


// LISTAR SETORES

app.get('/setores', auth, async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM setores ORDER BY nome');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});





// DELETAR LOJA SOMENTE SE FOR USUARIO ADM

app.delete('/lojas/:id', auth, async (req, res) => {
  if (req.user.nivel !== 'adm') {
    return res.status(403).json({ erro: 'Sem permissão' });
  }

  await db.query('DELETE FROM lojas WHERE id = ?', [req.params.id]);

  res.json({ sucesso: true });
});


// DELETAR SETORES SOMENTE SE USUARIO FOR ADM E SETOR NÃO ESTIVER EM USO

// 🗑️ DELETAR SETOR
app.delete('/setores/:id', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    const [rows] = await db.query(
      'SELECT * FROM setores WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Setor não encontrado' });
    }

    const setorNome = rows[0].nome;

    // 🔥 verifica uso
    const [emUso] = await db.query(
      'SELECT id FROM chamados WHERE setor = ? LIMIT 1',
      [setorNome]
    );

    if (emUso.length > 0) {
      return res.status(400).json({
        erro: `O setor "${setorNome}" está em uso e não pode ser deletado`
      });
    }

    await db.query('DELETE FROM setores WHERE id = ?', [id]);

    console.log('🗑️ SETOR DELETADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO DELETE SETOR:', err);
    res.status(500).json({ erro: err.message });
  }
});


// inativar lojas

app.put('/lojas/:id/inativar', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    await db.query(
      'UPDATE lojas SET ativo = FALSE WHERE id = ?',
      [id]
    );

    res.json({ sucesso: true });

  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});


// ativar lojas

app.put('/lojas/:id/ativar', auth, async (req, res) => {
  try {
    const { id } = req.params;

    await db.query(
      'UPDATE lojas SET ativo = TRUE WHERE id = ?',
      [id]
    );

    res.json({ sucesso: true });

  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});


// INATIVAR OS SETORES

app.put('/setores/:id/inativar', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    // 🔍 verifica se existe
    const [rows] = await db.query(
      'SELECT id FROM setores WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Setor não encontrado' });
    }

    // 🔴 inativa
    await db.query(
      'UPDATE setores SET ativo = 0 WHERE id = ?',
      [id]
    );

    console.log('🔴 SETOR INATIVADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO INATIVAR SETOR:', err);
    res.status(500).json({ erro: err.message });
  }
});



// ATIVAR OS SETORES

app.put('/setores/:id/ativar', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    // 🔍 verifica se existe
    const [rows] = await db.query(
      'SELECT id FROM setores WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Setor não encontrado' });
    }

    // 🟢 ativa
    await db.query(
      'UPDATE setores SET ativo = 1 WHERE id = ?',
      [id]
    );

    console.log('🟢 SETOR ATIVADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO ATIVAR SETOR:', err);
    res.status(500).json({ erro: err.message });
  }
}); 


//================= CRIAR DEPARTAMENTO =======================//

app.post('/departamentos', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { nome } = req.body;

    if (!nome || !nome.trim()) {
      return res.status(400).json({ erro: 'Nome é obrigatório' });
    }

    await db.query(
      'INSERT INTO departamentos (nome) VALUES (?)',
      [nome.trim()]
    );

    console.log('🏢 DEPARTAMENTO CRIADO:', nome);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO CRIAR DEPARTAMENTO:', err);
    res.status(500).json({ erro: err.message });
  }
});



//================= LISTAR DEMPARTAMENTOS ====================//

app.get('/departamentos', auth, async (req, res) => {
  try {
    const { ativo } = req.query;

    let sql = 'SELECT * FROM departamentos';

    if (ativo === '1') {
      sql += ' WHERE ativo = 1';
    }

    const [rows] = await db.query(sql);

    res.json(rows);

  } catch (err) {
    console.log('💥 ERRO LISTAR DEPARTAMENTOS:', err);
    res.status(500).json({ erro: err.message });
  }
});

//==================== INATIVAR DEPARTAMENTO =================//

app.put('/departamentos/:id/inativar', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    const [rows] = await db.query(
      'SELECT id FROM departamentos WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Departamento não encontrado' });
    }

    await db.query(
      'UPDATE departamentos SET ativo = 0 WHERE id = ?',
      [id]
    );

    console.log('🔴 DEPARTAMENTO INATIVADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO INATIVAR:', err);
    res.status(500).json({ erro: err.message });
  }
});


//===================== ATIVAR DEPARTMANETO ===================//

app.put('/departamentos/:id/ativar', auth, async (req, res) => {
  try {
    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { id } = req.params;

    const [rows] = await db.query(
      'SELECT id FROM departamentos WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Departamento não encontrado' });
    }

    await db.query(
      'UPDATE departamentos SET ativo = 1 WHERE id = ?',
      [id]
    );

    console.log('🟢 DEPARTAMENTO ATIVADO:', id);

    res.json({ sucesso: true });

  } catch (err) {
    console.log('💥 ERRO ATIVAR:', err);
    res.status(500).json({ erro: err.message });
  }
});


//================== LISTAR CEASA ITENS ====================//

app.get('/ceasa-itens', auth, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT * FROM ceasa_itens
      WHERE ativo = 1
      ORDER BY categoria, ordem
    `);

    res.json(rows);

  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});


//===================CRIAR COTAÇÃO===================//

app.post('/ceasa', auth, async (req, res) => {
  try {

    const { cotacao_id, itens } = req.body;

    const loja = req.user.loja;
    const usuario = req.user.nome;

    // 🔥 valida loja
    if (!loja) {
      return res.status(400).json({
        erro: 'Usuário não está vinculado a uma loja'
      });
    }

    // 🔥 valida cotação
    if (!cotacao_id) {
      return res.status(400).json({
        erro: 'Cotação não informada'
      });
    }

    // 🔥 valida itens
    if (!Array.isArray(itens)) {
      return res.status(400).json({
        erro: 'Formato de itens inválido'
      });
    }

    // 🔥 limpar itens
    const itensFiltrados = itens
      .map(i => ({
        nome: i.nome,
        quantidade: Number(i.quantidade || 0)
      }))
      .filter(i => i.nome && i.quantidade > 0);

    if (itensFiltrados.length === 0) {
      return res.status(400).json({
        erro: 'Nenhum item com quantidade válida'
      });
    }

    // 🔍 verifica se já existe resposta da loja nessa cotação
   /* const [existe] = await db.query(
      'SELECT id FROM ceasa_respostas WHERE loja = ? AND cotacao_id = ?',
      [loja, cotacao_id]
    );
*/
    if (existe.length > 0) {

      // 🔄 ATUALIZA
      await db.query(
        'UPDATE ceasa_respostas SET itens = ? WHERE id = ?',
        [JSON.stringify(itensFiltrados), existe[0].id]
      );

      console.log(`🔄 Pedido atualizado - Loja: ${loja}`);

    } else {

      // ➕ CRIA
      await db.query(
        `INSERT INTO ceasa_respostas (cotacao_id, loja, usuario, itens)
         VALUES (?, ?, ?, ?)`,
        [cotacao_id, loja, usuario, JSON.stringify(itensFiltrados)]
      );

      console.log(`➕ Novo pedido - Loja: ${loja}`);

    }

    res.json({ sucesso: true });

  } catch (err) {
    console.log('❌ ERRO CEASA:', err);
    res.status(500).json({ erro: err.message });
  }
});

//===============LISTAR COTAÇÃO ABERTA================//

app.get('/ceasa-cotacao-aberta', auth, async (req, res) => {
  try {

    const [rows] = await db.query(`
      SELECT *
      FROM cotacoes
      WHERE setor = 'CEASA' AND status = 'aberta'
      ORDER BY id DESC
      LIMIT 1
    `);

    if (rows.length === 0) {
      return res.json(null);
    }

    res.json(rows[0]);

  } catch (err) {
    console.log('❌ ERRO COTAÇÃO:', err);
    res.status(500).json({ erro: err.message });
  }
});


//=======================FECHAR COTAÇÃO==================//

app.put('/ceasa-cotacoes/:id/fechar', auth, async (req, res) => {
  try {

    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    await db.query(
      `UPDATE cotacoes 
       SET status = 'fechada'
       WHERE id = ?`,
      [req.params.id]
    );

    res.json({ sucesso: true });

  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

//=====================CEASA COTACOES================//

app.get('/ceasa-cotacoes', auth, async (req, res) => {
  const [rows] = await db.query(
    'SELECT * FROM cotacoes WHERE setor = "CEASA" ORDER BY id DESC'
  );

  res.json(rows);
});
//===================== DASHBOARD =================//
/*
app.get('/ceasa-dashboard', auth, async (req, res) => {
  try {

    // 🔥 pega a data mais recente
    const [respostas] = await db.query(`
  SELECT loja, itens
  FROM ceasa_respostas
  WHERE data >= DATE_SUB(CURDATE(), INTERVAL 2 DAY)
`);

    console.log('📦 RESPOSTAS:', respostas);

    const resultado = {};

    respostas.forEach(r => {

      if (!r.loja) return;

      let itens = [];

      if (typeof r.itens === 'string') {
        try {
          itens = JSON.parse(r.itens);
        } catch (e) {
          console.log('❌ JSON inválido:', r.itens);
          return;
        }
      } else {
        itens = r.itens;
      }

      itens.forEach(i => {

        if (!i.nome) return;

        const qtd = Number(i.quantidade || 0);
        if (qtd <= 0) return;

        if (!resultado[i.nome]) {
          resultado[i.nome] = {
            nome: i.nome,
            lojas: {},
            total: 0
          };
        }

        resultado[i.nome].lojas[r.loja] =
          (resultado[i.nome].lojas[r.loja] || 0) + qtd;

        resultado[i.nome].total += qtd;

      });
    });

    const lista = Object.values(resultado).sort((a, b) => b.total - a.total);

    const lojasSet = new Set();

    lista.forEach(item => {
      Object.keys(item.lojas).forEach(l => lojasSet.add(l));
    });

    const lojas = Array.from(lojasSet);

    res.json({
      itens: lista,
      lojas
    });

  } catch (err) {
    console.log('❌ ERRO DASHBOARD:', err);
    res.status(500).json({ erro: err.message });
  }
});
*/
//=============================================//

app.get('/ceasa-dashboard/:cotacaoId', auth, async (req, res) => {
  try {

    console.log('🔥 NOVA ROTA DASHBOARD SENDO USADA');
    
    const { cotacaoId } = req.params;

    // 🔥 busca cotação
    const [[cotacao]] = await db.query(
      'SELECT * FROM cotacoes WHERE id = ?',
      [cotacaoId]
    );

    // 🔥 busca respostas
    const [rows] = await db.query(
      'SELECT loja, itens FROM ceasa_respostas WHERE cotacao_id = ?',
      [cotacaoId]
    );

    const resultado = {};
    const lojasSet = new Set();

    rows.forEach(r => {

      let itens = [];

      // 🔥 CORREÇÃO DO ERRO JSON
      try {
        if (typeof r.itens === 'string') {
          itens = JSON.parse(r.itens);
        } else if (typeof r.itens === 'object') {
          itens = r.itens;
        } else {
          itens = [];
        }
      } catch (e) {
        console.log('❌ ERRO AO PARSEAR ITENS:', r.itens);
        itens = [];
      }

      lojasSet.add(r.loja);

      itens.forEach(i => {

        if (!i.nome) return;

        const qtd = Number(i.quantidade || 0);

        if (!resultado[i.nome]) {
          resultado[i.nome] = {
            nome: i.nome,
            lojas: {},
            total: 0
          };
        }

        resultado[i.nome].lojas[r.loja] =
          (resultado[i.nome].lojas[r.loja] || 0) + qtd;

        resultado[i.nome].total += qtd;

      });

    });

    const lista = Object.values(resultado).sort((a, b) => b.total - a.total);

    res.json({
      itens: lista,
      lojas: Array.from(lojasSet),
      cotacao
    });

  } catch (err) {
    console.log('❌ ERRO DASHBOARD:', err);
    res.status(500).json({ erro: err.message });
  }
});
//=========== CEASA CRIAR ITEM ===============//

app.post('/ceasa-itens', auth, async (req, res) => {
  try {

    if (req.user.nivel !== 'adm') {
      return res.status(403).json({ erro: 'Sem permissão' });
    }

    const { nome, categoria } = req.body;

    if (!nome || !categoria) {
      return res.status(400).json({ erro: 'Nome e categoria obrigatórios' });
    }

    await db.query(
      'INSERT INTO ceasa_itens (nome, categoria) VALUES (?, ?)',
      [nome, categoria]
    );

    res.json({ sucesso: true });

  } catch (error) {
    console.log('ERRO CEASA ITENS:', error);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

//=================== INATIVAR ITEM CEASA ======================//

app.put('/ceasa-itens/:id/inativar', auth, async (req, res) => {
  await db.query(
    'UPDATE ceasa_itens SET ativo = 0 WHERE id = ?',
    [req.params.id]
  );

  res.json({ sucesso: true });
});


//==================== ATIVAR ITEM CEASA =====================//

app.put('/ceasa-itens/:id/ativar', auth, async (req, res) => {
  await db.query(
    'UPDATE ceasa_itens SET ativo = 1 WHERE id = ?',
    [req.params.id]
  );

  res.json({ sucesso: true });
});


//================== rotas cotação ====================//

app.post('/cotacoes', auth, async (req, res) => {
  try {
    const { nome, setor } = req.body;

    if (!nome || !setor) {
      return res.status(400).json({
        erro: 'Nome e setor são obrigatórios'
      });
    }

    await db.query(
      `INSERT INTO cotacoes (nome, setor, status, data)
       VALUES (?, ?, 'aberta', CURDATE())`,
      [nome, setor]
    );

    res.json({ sucesso: true });

  } catch (err) {
    console.log('❌ ERRO AO CRIAR COTAÇÃO:', err);
    res.status(500).json({ erro: err.message });
  }
});


app.get('/cotacoes', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM cotacoes ORDER BY id DESC'
    );

    res.json(rows);

  } catch (err) {
    console.log(err);
    res.status(500).json({ erro: err.message });
  }
});



app.put('/cotacoes/:id/fechar', auth, async (req, res) => {
  try {
    await db.query(
      'UPDATE cotacoes SET status = "fechada" WHERE id = ?',
      [req.params.id]
    );

    res.json({ sucesso: true });

  } catch (err) {
    console.log(err);
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