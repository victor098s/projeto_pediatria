import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import pool from './db.js';
import { verificarAutenticacao } from './middleware/auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'chave_secreta_relacional_saep',
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 1000 * 60 * 60 },
    })
);

app.get('/login', (req, res) => res.render('login', { erro: null }));

app.post('/login', async (req, res) => {
    const { cpf, senha } = req.body;
    try {
        const { rows } = await pool.query(
            'SELECT id, nome, cpf, email, telefone, senha FROM clientes WHERE cpf = $1',
            [cpf]
        );
        if (!rows.length || !(await bcrypt.compare(senha, rows[0].senha))) {
            return res
                .status(401)
                .render('login', { erro: 'CPF ou senha inválidos.' });
        }
        const cliente = rows[0];
        req.session.usuario = {
            id: cliente.id,
            nome: cliente.nome,
            cpf: cliente.cpf,
            email: cliente.email,
            telefone: cliente.telefone,
        };
        res.redirect('/clientes');
    } catch (err) {
        console.error(err);
        res.status(500).render('login', {
            erro: 'Não foi possível entrar no sistema.',
        });
    }
});

app.post('/logout', (req, res) =>
    req.session.destroy(() => res.redirect('/login'))
);
// Mantém compatibilidade com links antigos sem expor logout por GET nos novos formulários.
app.get('/logout', (req, res) =>
    req.session.destroy(() => res.redirect('/login'))
);

app.get('/clientes', verificarAutenticacao, async (req, res) => {
    const busca = String(req.query.busca || '').trim();
    try {
        // A view reúne os dados do cliente e o nome do grupo associado.
        const resultado = await pool.query(
            `SELECT id, nome, cpf, email, telefone, nome_grupo
             FROM vw_cliente_completa
             WHERE $1 = '' OR concat_ws(' ', nome, cpf, email, telefone, nome_grupo) ILIKE $2
             ORDER BY id DESC`,
            [busca, `%${busca}%`]
        );
        res.render('clientes', {
            clientes: resultado.rows,
            usuario: req.session.usuario,
            busca,
            mensagem: req.query.mensagem || null,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send(
            'Erro ao carregar clientes. Confira a view vw_cliente_completa.'
        );
    }
});

app.get('/clientes/novo', verificarAutenticacao, async (req, res) => {
    try {
        const grupos = await pool.query(
            'SELECT id, nome_grupo FROM grupos ORDER BY nome_grupo'
        );
        res.render('cliente-novo', {
            grupos: grupos.rows,
            usuario: req.session.usuario,
            erro: null,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar grupos.');
    }
});

app.post('/clientes/novo', verificarAutenticacao, async (req, res) => {
    const { nome, cpf, email, telefone, senha, grupo_id } = req.body;
    try {
        const hash = await bcrypt.hash(senha, 10);
        await pool.query(
            'INSERT INTO clientes (nome, cpf, email, telefone, senha, grupo_id) VALUES ($1, $2, $3, $4, $5, $6)',
            [
                nome.trim(),
                cpf.trim(),
                email.trim(),
                telefone.trim(),
                hash,
                grupo_id || null,
            ]
        );
        res.redirect('/clientes?mensagem=Cliente+cadastrado+com+sucesso');
    } catch (err) {
        console.error(err);
        const grupos = await pool.query(
            'SELECT id, nome_grupo FROM grupos ORDER BY nome_grupo'
        );
        const erro =
            err.code === '23505'
                ? 'Já existe um cliente com esse CPF.'
                : 'Não foi possível cadastrar o cliente.';
        res.status(400).render('cliente-novo', {
            grupos: grupos.rows,
            usuario: req.session.usuario,
            erro,
        });
    }
});

app.get('/clientes/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const [cliente, grupos] = await Promise.all([
            pool.query(
                'SELECT id, nome, cpf, email, telefone, grupo_id FROM clientes WHERE id = $1',
                [req.params.id]
            ),
            pool.query('SELECT id, nome_grupo FROM grupos ORDER BY nome_grupo'),
        ]);
        if (!cliente.rows.length)
            return res.status(404).send('Cliente não encontrado.');
        res.render('editar-cliente', {
            cliente: cliente.rows[0],
            grupos: grupos.rows,
            usuario: req.session.usuario,
            erro: null,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar os dados do cliente.');
    }
});

app.post('/clientes/editar/:id', verificarAutenticacao, async (req, res) => {
    const { nome, cpf, email, telefone, grupo_id } = req.body;
    try {
        await pool.query(
            'UPDATE clientes SET nome = $1, cpf = $2, email = $3, telefone = $4, grupo_id = $5 WHERE id = $6',
            [
                nome.trim(),
                cpf.trim(),
                email.trim(),
                telefone.trim(),
                grupo_id || null,
                req.params.id,
            ]
        );
        res.redirect('/clientes?mensagem=Cliente+atualizado+com+sucesso');
    } catch (err) {
        console.error(err);
        const [cliente, grupos] = await Promise.all([
            pool.query(
                'SELECT id, nome, cpf, email, telefone, grupo_id FROM clientes WHERE id = $1',
                [req.params.id]
            ),
            pool.query('SELECT id, nome_grupo FROM grupos ORDER BY nome_grupo'),
        ]);
        const erro =
            err.code === '23505'
                ? 'Já existe um cliente com esse CPF.'
                : 'Não foi possível atualizar o cliente.';
        res.status(400).render('editar-cliente', {
            cliente: { ...cliente.rows[0], ...req.body },
            grupos: grupos.rows,
            usuario: req.session.usuario,
            erro,
        });
    }
});

app.post('/clientes/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        await pool.query('DELETE FROM clientes WHERE id = $1', [req.params.id]);
        res.redirect('/clientes?mensagem=Cliente+removido+com+sucesso');
    } catch (err) {
        console.error(err);
        res.status(500).send('Não foi possível remover o cliente.');
    }
});

app.get('/grupos', verificarAutenticacao, async (req, res) => {
    try {
        const resultado = await pool.query(
            `SELECT g.id, g.nome_grupo, count(c.id)::int AS total_clientes
             FROM grupos g LEFT JOIN clientes c ON c.grupo_id = g.id
             GROUP BY g.id, g.nome_grupo ORDER BY g.id`
        );
        res.render('grupos', {
            grupos: resultado.rows,
            usuario: req.session.usuario,
            erro: req.query.erro || null,
            mensagem: req.query.mensagem || null,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar grupos.');
    }
});

app.post('/grupos/novo', verificarAutenticacao, async (req, res) => {
    const nome = String(req.body.nome_grupo || '').trim();
    if (!nome) return res.redirect('/grupos?erro=Informe+o+nome+do+grupo');
    try {
        await pool.query('INSERT INTO grupos (nome_grupo) VALUES ($1)', [nome]);
        res.redirect('/grupos?mensagem=Grupo+cadastrado+com+sucesso');
    } catch (err) {
        console.error(err);
        const erro =
            err.code === '23505'
                ? 'Já existe um grupo com esse nome.'
                : 'Não foi possível cadastrar o grupo.';
        res.redirect(`/grupos?erro=${encodeURIComponent(erro)}`);
    }
});

app.get('/grupos/editar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const { rows } = await pool.query(
            'SELECT id, nome_grupo FROM grupos WHERE id = $1',
            [req.params.id]
        );
        if (!rows.length) return res.status(404).send('Grupo não encontrado.');
        res.render('editar-grupos', {
            grupo: rows[0],
            usuario: req.session.usuario,
            erro: null,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar os dados do grupo.');
    }
});

app.post('/grupos/editar/:id', verificarAutenticacao, async (req, res) => {
    const nome = String(req.body.nome_grupo || '').trim();
    const grupo = { id: req.params.id, nome_grupo: nome };

    if (!nome) {
        return res.status(400).render('editar-grupos', {
            grupo,
            usuario: req.session.usuario,
            erro: 'Informe o nome do grupo.',
        });
    }

    try {
        const resultado = await pool.query(
            'UPDATE grupos SET nome_grupo = $1 WHERE id = $2',
            [nome, req.params.id]
        );
        if (!resultado.rowCount)
            return res.status(404).send('Grupo não encontrado.');
        res.redirect('/grupos?mensagem=Grupo+atualizado+com+sucesso');
    } catch (err) {
        console.error(err);
        const erro =
            err.code === '23505'
                ? 'Já existe um grupo com esse nome.'
                : 'Não foi possível atualizar o grupo.';
        res.status(400).render('editar-grupos', {
            grupo,
            usuario: req.session.usuario,
            erro,
        });
    }
});

app.post('/grupos/deletar/:id', verificarAutenticacao, async (req, res) => {
    try {
        const uso = await pool.query(
            'SELECT 1 FROM clientes WHERE grupo_id = $1 LIMIT 1',
            [req.params.id]
        );
        if (uso.rowCount)
            return res.redirect(
                '/grupos?erro=Transfira+os+clientes+antes+de+excluir+este+grupo'
            );
        await pool.query('DELETE FROM grupos WHERE id = $1', [req.params.id]);
        res.redirect('/grupos');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao excluir grupo.');
    }
});

app.get('/', (req, res) =>
    res.redirect(req.session.usuario ? '/clientes' : '/login')
);

app.listen(process.env.PORT || 3000, () => {
    console.log(
        `Sistema de clientes e grupos disponível em http://localhost:${process.env.PORT || 3000}`
    );
});
