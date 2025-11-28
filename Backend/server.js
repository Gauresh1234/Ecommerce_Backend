const express = require("express");
const app = express();
const pool = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const PORT = 5000;
const JWT_SECRET = "a_very_secret_key_for_jwt_change_in_prod";

app.use(cors());
app.use(express.json());

async function ensureAdmin() {
  try {
    const [rows] = await pool.query("SELECT * FROM admin WHERE username = ?", [
      "admin",
    ]);
    if (rows.length === 0) {
      const hash = await bcrypt.hash("Admin@123", 10);
      await pool.query(
        "INSERT INTO admin (username, password_hash) VALUES (?, ?)",
        ["admin", hash]
      );
      console.log("Admin user created with username=admin password=Admin@123");
    } else {
      console.log("Admin exists.");
    }
  } catch (err) {
    console.error("ensureAdmin error:", err);
  }
}
ensureAdmin();

function verifyAdmin(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ message: "Admin token missing" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.admin) {
      return res.status(403).json({ message: "Not authorized" });
    }
    req.adminId = decoded.adminId;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid admin token" });
  }
}

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const [existing] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );
    if (existing.length)
      return res.status(400).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, hash]
    );
    const userId = result.insertId;

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ token, user: { id: userId, name, email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash FROM users WHERE email = ?",
      [email]
    );
    if (!rows.length)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const [rows] = await pool.query(
      "SELECT id, username, password_hash FROM admin WHERE username = ?",
      [username]
    );
    if (!rows.length)
      return res.status(401).json({ message: "Invalid admin credentials" });

    const admin = rows[0];
    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok)
      return res.status(401).json({ message: "Invalid admin credentials" });

    const token = jwt.sign({ adminId: admin.id, admin: true }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({ token, admin: { id: admin.id, username: admin.username } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/products", async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT p.*, s.name as seller_name FROM products p LEFT JOIN seller s ON p.seller_id = s.id"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const [rows] = await pool.query(
      "SELECT p.*, s.name as seller_name FROM products p LEFT JOIN seller s ON p.seller_id = s.id WHERE p.id = ?",
      [id]
    );
    if (!rows.length)
      return res.status(404).json({ message: "Product not found" });

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/admin/products", verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT p.*, s.name as seller_name FROM products p LEFT JOIN seller s ON p.seller_id = s.id"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/admin/products", verifyAdmin, async (req, res) => {
  try {
    const { seller_id, name, description, price, stock, image } = req.body;

    const [result] = await pool.query(
      "INSERT INTO products (seller_id, name, description, price, stock, image) VALUES (?, ?, ?, ?, ?, ?)",
      [seller_id, name, description, price, stock, image]
    );

    res.json({ message: "Product added", productId: result.insertId });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/admin/products/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { name, description, price, stock, image } = req.body;

    await pool.query(
      "UPDATE products SET name=?, description=?, price=?, stock=?, image=? WHERE id=?",
      [name, description, price, stock, image, id]
    );

    res.json({ message: "Product updated" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/admin/products/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    await pool.query("DELETE FROM products WHERE id=?", [id]);

    res.json({ message: "Product deleted" });
  } catch (err) {
    if (err.code === "ER_ROW_IS_REFERENCED_2") {
      return res.status(400).json({
        message: "Cannot delete product because it has orders linked to it.",
      });
    }
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/admin/sellers", verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM seller ORDER BY created_at DESC"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/api/admin/sellers/:id/approve", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query("UPDATE seller SET status='approved' WHERE id=?", [id]);
    res.json({ message: "Seller approved" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/api/admin/sellers/:id", verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query("DELETE FROM seller WHERE id=?", [id]);
    res.json({ message: "Seller deleted" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/orders", async (req, res) => {
  try {
    const { userId, items, total } = req.body;
    if (!userId || !items || !items.length)
      return res.status(400).json({ message: "Invalid order" });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [orderRes] = await conn.query(
        "INSERT INTO orders (user_id, total, status) VALUES (?, ?, ?)",
        [userId, total, "placed"]
      );
      const orderId = orderRes.insertId;

      for (const it of items) {
        const [p] = await conn.query(
          "SELECT price FROM products WHERE id = ?",
          [it.product_id]
        );
        const unit_price = p.length ? p[0].price : it.unit_price || 0;

        await conn.query(
          "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)",
          [orderId, it.product_id, it.quantity, unit_price]
        );

        await conn.query(
          "UPDATE products SET stock = GREATEST(stock - ?, 0) WHERE id = ?",
          [it.quantity, it.product_id]
        );
      }

      await conn.commit();
      res.json({ message: "Order placed", orderId });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/admin/orders", verifyAdmin, async (req, res) => {
  try {
    const [orders] = await pool.query(
      "SELECT o.*, u.name as user_name, u.email as user_email FROM orders o LEFT JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC"
    );

    for (const o of orders) {
      const [items] = await pool.query(
        "SELECT oi.*, p.name as product_name FROM order_items oi LEFT JOIN products p ON oi.product_id = p.id WHERE oi.order_id = ?",
        [o.id]
      );
      o.items = items;
    }

    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/admin/users", verifyAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, created_at FROM users ORDER BY created_at DESC"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.listen(PORT, () => console.log("Server running on port", PORT));
