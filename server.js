const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcrypt');

const app = express();

app.use(express.json({ limit: '50mb' }));
app.use(cors());


// 🔥 CONEXÃO MYSQL (CORRIGIDA)
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false
  }
}).promise();


// 🔥 TESTE DE CONEXÃO
(async () => {
  try {
    await db.query('SELECT 1');
    console.log('✅ MYSQL CONECTADO');
  } catch (err) {
    console.log('❌ ERRO MYSQL:', err);
  }
})();





/*db.connect((err) => {
  if (err) {
    console.log('Erro MySQL:', err);
    return;
  }
  console.log('MySQL conectado');
});*/


// =========================
// 🔔 FUNÇÃO NOTIFICAÇÃO
// =========================
async function enviarNotificacao(tokens, chamado) {
  const mensagens = tokens.map(token => ({
    to: token,
    sound: 'default',
    title: '🔧 Novo chamado',
    body: `${chamado.titulo} - ${chamado.loja}`,
    
    data: {
      id: chamado.id // 🔥 ESSENCIAL
    }
  }));

  await fetch('https://exp.host/--/api/v2/push/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(mensagens)
  });
}


// =========================
// 🔐 LOGIN
// =========================
app.post('/login', (req, res) => {
  const { nome, senha } = req.body;

  const sql = 'SELECT * FROM usuarios WHERE nome = ?';

  db.query(sql, [nome], async (err, result) => {
    if (err) {
      console.log('ERRO LOGIN:', err);
      return res.status(500).send(err);
    }

    if (result.length === 0) {
      return res.status(401).json({ erro: 'Usuário inválido' });
    }

    const usuario = result[0];

    const senhaValida = await bcrypt.compare(senha, usuario.senha);

    if (!senhaValida) {
      return res.status(401).json({ erro: 'Senha inválida' });
    }

    res.json(usuario);
  });
});


// =========================
// 👤 USUÁRIOS
// =========================

// 🔥 LISTAR
app.get('/usuarios', (req, res) => {
  db.query('SELECT * FROM usuarios', (err, result) => {
    if (err) return res.status(500).json(err);
    res.json(result);
  });
});

// 🔥 CRIAR
app.post('/usuarios', async (req, res) => {
  const { nome, senha, nivel, departamento, loja } = req.body;

  try {
    const senhaHash = await bcrypt.hash(senha, 10);

    const sql = `
      INSERT INTO usuarios (nome, senha, nivel, departamento, loja)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [nome, senhaHash, nivel, departamento, loja],
      (err) => {
        if (err) {
          console.log('❌ Erro ao criar usuário:', err);
          return res.status(500).json(err);
        }

        res.json({ message: 'Usuário criado com sucesso' });
      }
    );

  } catch (error) {
    console.log('❌ ERRO HASH:', error);
    res.status(500).json({ erro: 'Erro ao criptografar senha' });
  }
});

// 🔥 SALVAR TOKEN PUSH
app.post('/usuarios/token', (req, res) => {
  const { usuario, token } = req.body;

  const sql = `UPDATE usuarios SET token = ? WHERE nome = ?`;

  db.query(sql, [token, usuario], (err) => {
    if (err) {
      console.log('❌ Erro token:', err);
      return res.status(500).json(err);
    }

    res.json({ sucesso: true });
  });
});


// ========= alterar senha ========

app.put('/usuarios/alterar-senha', (req, res) => {
  const { nome, senhaAtual, novaSenha } = req.body;

  const sql = 'SELECT * FROM usuarios WHERE nome = ?';

  db.query(sql, [nome], async (err, result) => {
    if (err) {
      console.log('❌ ERRO:', err);
      return res.status(500).json({ erro: 'Erro no servidor' });
    }

    if (result.length === 0) {
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    }

    const usuario = result[0];

    const senhaValida = await bcrypt.compare(senhaAtual, usuario.senha);

    if (!senhaValida) {
      return res.status(400).json({ erro: 'Senha atual incorreta' });
    }

    const novaSenhaHash = await bcrypt.hash(novaSenha, 10);

    const updateSql = `
      UPDATE usuarios
      SET senha = ?
      WHERE nome = ?
    `;

    db.query(updateSql, [novaSenhaHash, nome], (err) => {
      if (err) {
        console.log('❌ ERRO UPDATE:', err);
        return res.status(500).json({ erro: 'Erro ao atualizar senha' });
      }

      res.json({ sucesso: true });
    });
  });
});






// 🔥 EDITAR
app.put('/usuarios/:id', async (req, res) => {
  const { id } = req.params;
  const { senha, nivel, departamento, loja } = req.body;

  let campos = [];
  let valores = [];

  if (senha) {
    const hash = await bcrypt.hash(senha, 10); // 🔥 AQUI
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

  db.query(sql, valores, (err, result) => {
    if (err) {
      console.log('❌ ERRO SQL:', err);
      return res.status(500).json({ erro: err.message });
    }

    res.json({ sucesso: true });
  });
});
// 🔥 DELETAR
app.delete('/usuarios/:id', (req, res) => {
  const { id } = req.params;

  const sql = 'DELETE FROM usuarios WHERE id = ?';

  db.query(sql, [id], (err) => {
    if (err) {
      console.log('❌ ERRO DELETE:', err);
      return res.status(500).json({ erro: err.message });
    }

    res.json({ sucesso: true });
  });
});



app.post('/usuarios/token', (req, res) => {
  const { usuario, token } = req.body;

  console.log('📱 Salvando token:', usuario, token);

  const sql = 'UPDATE usuarios SET token = ? WHERE nome = ?';

  db.query(sql, [token, usuario], (err) => {
    if (err) {
      console.log('❌ Erro ao salvar token:', err);
      return res.status(500).json({ erro: 'Erro ao salvar token' });
    }

    res.json({ sucesso: true });
  });
});




// =========================
// 📄 CHAMADOS
// =========================

// 🔥 CRIAR CHAMADO + NOTIFICAÇÃO
app.post('/chamados', (req, res) => {
  try {
    const {
      titulo,
      descricao,
      loja,
      setor,
      status,
      usuario,
      departamento,
      fotos,
      sn
    } = req.body;

    const fotosJSON = fotos && Array.isArray(fotos)
      ? JSON.stringify(fotos)
      : '[]';

    const sql = `
      INSERT INTO chamados 
      (titulo, descricao, loja, setor, status, criadoPor, departamento, fotos, sn, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    db.query(
      sql,
      [
        titulo,
        descricao,
        loja,
        setor,
        status,
        usuario, // 🔥 agora vai para criadoPor
        departamento,
        fotosJSON,
        sn || null
      ],
      (err, result) => {
        if (err) {
          console.log('❌ ERRO MYSQL:', err);
          return res.status(500).json({ erro: err.message });
        }

        const chamadoCriado = {
          id: result.insertId,
          titulo,
          loja
        };

        // 🔥 NOTIFICAÇÃO
        db.query(
          "SELECT token FROM usuarios WHERE departamento = 'manutencao' AND token IS NOT NULL",
          (err2, users) => {
            if (!err2 && users.length > 0) {
              const tokens = users.map(u => u.token);
              enviarNotificacao(tokens, chamadoCriado);
            }
          }
        );

        res.json({ sucesso: true });
      }
    );

  } catch (error) {
    console.log('💥 ERRO GERAL:', error);
    res.status(500).json({ erro: error.message });
  }
});


// 🔥 LISTAR CHAMADOS
// 🔥 LISTAR CHAMADOS (CORRIGIDO)
app.get('/chamados', async (req, res) => {
  try {
    const [result] = await db.query('SELECT * FROM chamados');

    const chamados = result.map((c) => ({
      ...c,

      fotos: (() => {
        try {
          return JSON.parse(c.fotos);
        } catch {
          return c.fotos ? [c.fotos] : [];
        }
      })(),

      criadoPor: c.criadoPor || c.usuario || null,
      assumidoPor: c.assumidoPor || null,
      finalizadoPor: c.finalizadoPor || null,
      dataFinalizacao: c.dataFinalizacao || null,
      dataAssumido: c.dataAssumido || null,
      sn: c.sn || null
    }));

    res.json(chamados);

  } catch (err) {
    console.log('❌ ERRO GET:', err);
    res.status(500).json({ erro: err.message });
  }
});
app.put('/chamados/:id', (req, res) => {
  const { id } = req.params;
  const { status, usuario } = req.body;

  let sql = `UPDATE chamados SET status = ?`;
  let valores = [status];

  // 🔥 ASSUMIR
if (status?.toUpperCase() === 'ANDAMENTO') {
  sql += `, assumidoPor = ?, dataAssumido = NOW()`;
  valores.push(usuario);
}

  // 🔥 FINALIZAR
  if (status?.toUpperCase() === 'FINALIZADO') {
    sql += `, finalizadoPor = ?, dataFinalizacao = NOW()`;
    valores.push(usuario);
  }

  sql += ` WHERE id = ?`;
  valores.push(id);

  db.query(sql, valores, (err, result) => {
    if (err) {
      console.log('❌ ERRO:', err);
      return res.status(500).json(err);
    }

    console.log('✅ UPDATE:', result);

    res.json({ sucesso: true });
  });
});






// =========================

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});