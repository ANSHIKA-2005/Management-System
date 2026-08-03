const express = require("express");
const path    = require("path");
const db      = require("./db");
const crypto  = require("crypto");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

console.log("Server starting...");

// ── Active tokens ──────────────────────────────────────
const activeTokens = {};

function generateToken() {
    return crypto.randomBytes(32).toString("hex");
}

function getUserFromToken(req) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return null;
    const token = authHeader.replace("Bearer ", "");
    return activeTokens[token] || null;
}

// ── Auth Middleware ───────────────────────────────────────────────
function requireAuth(req, res, next) {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ message: "Please login first" });
    req.user = user;
    next();
}

// ── Root → login page ─────────────────────────────────────────────
app.get("/", (req, res) => {
    res.redirect("/login.html");
});

// Register
app.post("/auth/register", (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
        return res.status(400).json({ message: "All fields required" });

    if (password.length < 6)
        return res.status(400).json({ message: "Password must be at least 6 characters" });

    db.query("SELECT id FROM Users WHERE email = ?", [email], (err, result) => {
        if (err)  return res.status(500).json({ message: err.message });
        if (result.length > 0)
            return res.status(400).json({ message: "Email already registered" });

        db.query(
            "INSERT INTO Users (name, email, password) VALUES (?, ?, ?)",
            [name, email, password],
            (err2) => {
                if (err2) return res.status(500).json({ message: err2.message });
                res.json({ message: "Account created successfully" });
            }
        );
    });
});

// Login — sirf database check
app.post("/auth/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ message: "Email and password required" });

    db.query("SELECT * FROM Users WHERE email = ?", [email], (err, result) => {
        if (err) return res.status(500).json({ message: err.message });

        if (result.length === 0)
            return res.status(401).json({ message: "Invalid email or password" });

        const user = result[0];

        if (user.password !== password)
            return res.status(401).json({ message: "Invalid email or password" });

        const token    = generateToken();
        const userData = { id: user.id, name: user.name, email: user.email };
        activeTokens[token] = userData;
        res.json({ token, user: userData });
    });
});

// Verify token
app.get("/auth/verify", (req, res) => {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ message: "Invalid or expired token" });
    res.json({ user });
});

// Logout
app.post("/auth/logout", (req, res) => {
    const authHeader = req.headers["authorization"];
    if (authHeader) {
        const token = authHeader.replace("Bearer ", "");
        delete activeTokens[token];
    }
    res.json({ message: "Logged out successfully" });
});

// ═══════════════════════════════════════════════════════════════════
// STUDENTS
// ═══════════════════════════════════════════════════════════════════

app.get("/students", requireAuth, (req, res) => {
    db.query("SELECT * FROM Students", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

app.post("/students", requireAuth, (req, res) => {
    const { student_id, first_name, last_name, email, enrollment_date } = req.body;
    db.query(
        "INSERT INTO Students(student_id, first_name, last_name, email, enrollment_date) VALUES (?, ?, ?, ?, ?)",
        [student_id, first_name, last_name, email, enrollment_date],
        (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ message: "Student Added Successfully" });
        }
    );
});

app.put("/students/:id", requireAuth, (req, res) => {
    const { first_name, last_name, email, enrollment_date } = req.body;
    db.query(
        "UPDATE Students SET first_name=?, last_name=?, email=?, enrollment_date=? WHERE student_id=?",
        [first_name, last_name, email, enrollment_date, req.params.id],
        (err) => {
            if (err) return res.status(500).json(err);
            res.json({ message: "Student updated successfully" });
        }
    );
});

app.get("/students/:id/enrollment-count", requireAuth, (req, res) => {
    db.query(
        "SELECT COUNT(*) AS count FROM Enrollments WHERE student_id = ?",
        [req.params.id],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ count: result[0].count });
        }
    );
});

app.delete("/students/:id", requireAuth, (req, res) => {
    const id = req.params.id;
    const cascade = req.query.cascade === "true";

    const deleteStudent = () => {
        db.query("DELETE FROM Students WHERE student_id = ?", [id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Student deleted successfully" });
        });
    };

    if (cascade) {
        db.query("DELETE FROM Enrollments WHERE student_id = ?", [id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            deleteStudent();
        });
    } else {
        deleteStudent();
    }
});

// ═══════════════════════════════════════════════════════════════════
// COURSES
// ═══════════════════════════════════════════════════════════════════

app.get("/courses", requireAuth, (req, res) => {
    db.query("SELECT * FROM Courses", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

app.post("/courses", requireAuth, (req, res) => {
    const { course_id, course_name, instructor, credits } = req.body;
    db.query(
        "INSERT INTO Courses (course_id, course_name, instructor, credits) VALUES (?, ?, ?, ?)",
        [course_id, course_name, instructor, credits],
        (err) => {
            if (err) return res.status(500).json(err);
            res.json({ message: "Course added successfully" });
        }
    );
});

app.put("/courses/:id", requireAuth, (req, res) => {
    const { course_name, instructor, credits } = req.body;
    db.query(
        "UPDATE Courses SET course_name=?, instructor=?, credits=? WHERE course_id=?",
        [course_name, instructor, credits, req.params.id],
        (err) => {
            if (err) return res.status(500).json(err);
            res.json({ message: "Course updated successfully" });
        }
    );
});

app.get("/courses/:id/enrollment-count", requireAuth, (req, res) => {
    db.query(
        "SELECT COUNT(*) AS count FROM Enrollments WHERE course_id = ?",
        [req.params.id],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ count: result[0].count });
        }
    );
});

app.delete("/courses/:id", requireAuth, (req, res) => {
    const id = req.params.id;
    const cascade = req.query.cascade === "true";

    const deleteCourse = () => {
        db.query("DELETE FROM Courses WHERE course_id=?", [id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Course deleted successfully" });
        });
    };

    if (cascade) {
        db.query("DELETE FROM Enrollments WHERE course_id = ?", [id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            deleteCourse();
        });
    } else {
        deleteCourse();
    }
});

// ═══════════════════════════════════════════════════════════════════
// ENROLLMENTS
// ═══════════════════════════════════════════════════════════════════

app.get("/enrollments", requireAuth, (req, res) => {
    db.query("SELECT * FROM Enrollments", (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

app.post("/enrollments", requireAuth, (req, res) => {
    const { enrollment_id, student_id, course_id, enrollment_date, grade } = req.body;
    db.query(
        "INSERT INTO Enrollments (enrollment_id, student_id, course_id, enrollment_date, grade) VALUES (?, ?, ?, ?, ?)",
        [enrollment_id, student_id, course_id, enrollment_date, grade],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Enrollment added successfully" });
        }
    );
});

app.put("/enrollments/:id", requireAuth, (req, res) => {
    const { student_id, course_id, enrollment_date, grade } = req.body;
    db.query(
        "UPDATE Enrollments SET student_id=?, course_id=?, enrollment_date=?, grade=? WHERE enrollment_id=?",
        [student_id, course_id, enrollment_date, grade, req.params.id],
        (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Enrollment updated successfully" });
        }
    );
});

app.delete("/enrollments/:id", requireAuth, (req, res) => {
    db.query("DELETE FROM Enrollments WHERE enrollment_id=?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Enrollment deleted successfully" });
    });
});

// ═══════════════════════════════════════════════════════════════════
// SEARCH / LOOKUP
// ═══════════════════════════════════════════════════════════════════

app.get("/student-courses/:id", requireAuth, (req, res) => {
    const sql = `
        SELECT s.student_id, CONCAT(s.first_name,' ',s.last_name) AS student_name,
               c.course_name, c.instructor, e.grade
        FROM Students s
        JOIN Enrollments e ON s.student_id = e.student_id
        JOIN Courses c     ON e.course_id  = c.course_id
        WHERE s.student_id = ?`;
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json(err);
        res.json(result);
    });
});

app.get("/student-course-detail", requireAuth, (req, res) => {
    const { student_id, course_id } = req.query;
    if (!student_id || !course_id)
        return res.status(400).json({ error: "student_id and course_id required" });

    const sql = `
        SELECT s.student_id, CONCAT(s.first_name,' ',s.last_name) AS student_name,
               s.email, c.course_id, c.course_name, c.instructor, c.credits,
               e.enrollment_id, e.enrollment_date, e.grade
        FROM Students s
        JOIN Enrollments e ON s.student_id = e.student_id
        JOIN Courses c     ON e.course_id  = c.course_id
        WHERE s.student_id = ? AND c.course_id = ?
        LIMIT 1`;
    db.query(sql, [student_id, course_id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result[0] || {});
    });
});

app.get("/course-students-by-name", requireAuth, (req, res) => {
    const name = req.query.name;
    if (!name) return res.status(400).json({ error: "name query param required" });

    const sql = `
        SELECT c.course_id, c.course_name, c.instructor, c.credits,
               s.student_id, CONCAT(s.first_name,' ',s.last_name) AS student_name,
               e.enrollment_date, e.grade
        FROM Courses c
        JOIN Enrollments e ON c.course_id  = e.course_id
        JOIN Students s    ON e.student_id = s.student_id
        WHERE c.course_name LIKE ?
        ORDER BY s.last_name, s.first_name`;
    db.query(sql, [`%${name}%`], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result);
    });
});

app.get("/course-students/:id", requireAuth, (req, res) => {
    const sql = `
        SELECT c.course_id, c.course_name, s.student_id,
               CONCAT(s.first_name,' ',s.last_name) AS student_name, e.grade
        FROM Courses c
        JOIN Enrollments e ON c.course_id  = e.course_id
        JOIN Students s    ON e.student_id = s.student_id
        WHERE c.course_id = ?`;
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json(err);
        res.json(result);
    });
});

app.get("/report-card/:id", requireAuth, (req, res) => {
    const sql = `
        SELECT s.student_id, CONCAT(s.first_name,' ',s.last_name) AS student_name,
               c.course_name, c.instructor, c.credits, e.grade
        FROM Students s
        JOIN Enrollments e ON s.student_id = e.student_id
        JOIN Courses c     ON e.course_id  = c.course_id
        WHERE s.student_id = ?`;
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json(err);
        res.json(result);
    });
});

// ═══════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════

app.get("/dashboard", requireAuth, (req, res) => {
    const sql = `
        SELECT
            (SELECT COUNT(*) FROM Students)    AS total_students,
            (SELECT COUNT(*) FROM Courses)     AS total_courses,
            (SELECT COUNT(*) FROM Enrollments) AS total_enrollments,
            (SELECT AVG(credits) FROM Courses) AS avg_credits`;
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json(err);
        res.json(result[0]);
    });
});

app.get("/course-popularity", requireAuth, (req, res) => {
    const sql = `
        SELECT c.course_name, COUNT(e.student_id) AS students_enrolled
        FROM Courses c
        LEFT JOIN Enrollments e ON c.course_id = e.course_id
        GROUP BY c.course_id
        ORDER BY students_enrolled DESC`;
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json(err);
        res.json(result);
    });
});

// ── Start server ──────────────────────────────────────────────────
app.listen(3009, () => {
    console.log("Server running on http://localhost:3009");
});