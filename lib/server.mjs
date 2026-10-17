/*!
 * kidlat - security
 * Copyright(c) 2026 JoshLei
 * MIT Licensed
 */

// Target app for fuzz and soak. Runs as a child process so crashes and memory are observable.
import { Kidlat } from 'kidlat';

const app = new Kidlat({ logger: false });
app.get('/', () => ({ ok: true }));
app.post('/echo', async (req) => ({ len: (await req.buffer()).length }));
app.get('/users/:id', (req) => ({ id: req.params.id }));
app.get('/__mem', () => process.memoryUsage());

const port = app.listen(Number(process.env.PORT || 0));
process.send?.({ port });
