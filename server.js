require("dotenv").config();
const express = require("express");
const path    = require("path");
const db      = require("./db");
// const crypto  = require("crypto");
const bcrypt = require("bcrypt");
const jwt     = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

console.log("Server starting...");

const JWT_SECRET = process.env.JWT_SECRET;

function getUserFromToken(req) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return null;
    const token = authHeader.replace("Bearer ", "");
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return decoded;
    } catch (err) {
        return null;
    }
}

// ── Auth Middleware ───────────────────────────────────────────────
function requireAuth(req, res, next) {
    const user = getUserFromToken(req);
    if (!user) return res.status(401).json({ message: "Please login first" });
    req.user = user;
    next();
}

function requireTeacher(req, res, next) {
    if (req.user.role !== 'teacher') {
        return res.status(403).json({ message: "Only teachers can perform this action" });
    }
    next();
}

// ── Root → login page ─────────────────────────────────────────────
app.get("/", (req, res) => {
    res.redirect("/login.html");
});

// Register
// app.post("/auth/register", (req, res) => {
//     const { name, email, password, role } = req.body;

//     if (!name || !email || !password)
//         return res.status(400).json({ message: "All fields required" });

//     if (password.length < 6)
//         return res.status(400).json({ message: "Password must be at least 6 characters" });

//     db.query("SELECT id FROM Users WHERE email = ?", [email], async(err, result) => {
//         if (err)  return res.status(500).json({ message: err.message });
//         if (result.length > 0)
//             return res.status(400).json({ message: "Email already registered" });
//         const hashedPassword = await bcrypt.hash(password, 10);

//         db.query(
//             "INSERT INTO Users (name, email, password, role) VALUES (?, ?, ?, ?)",
//             [name, email, hashedPassword, role || 'student'],
//             (err2) => {
//                 if (err2) return res.status(500).json({ message: err2.message });
//                 res.json({ message: "Account created successfully" });
//             }
//         );
//     });
// });

app.post("/auth/register", (req, res) => {
    const { name, email, password, student_id, role } = req.body;

    if (!name || !email || !password)
        return res.status(400).json({ message: "All fields required" });

    if (password.length < 6)
        return res.status(400).json({ message: "Password must be at least 6 characters" });

    db.query("SELECT id FROM Users WHERE email = ?", [email], async (err, result) => {
        if (err) return res.status(500).json({ message: "Something went wrong" });
        if (result.length > 0)
            return res.status(400).json({ message: "Email already registered" });

        if (student_id) {
            // Check 1: student_id genuinely Students table mein exist karta hai?
            db.query("SELECT * FROM Students WHERE student_id = ?", [student_id], (err2, studentRows) => {
                if (err2) return res.status(500).json({ message: "Something went wrong" });
                if (studentRows.length === 0) {
                    return res.status(400).json({ message: "Invalid Student ID — no matching student record found" });
                }

                // Check 2: student_id already kisi Users-account se linked hai?
                db.query("SELECT * FROM Users WHERE student_id = ?", [student_id], async (err3, linkedRows) => {
                    if (err3) return res.status(500).json({ message: "Something went wrong" });
                    if (linkedRows.length > 0) {
                        return res.status(400).json({ message: "This Student ID is already registered to another account" });
                    }

                    const hashedPassword = await bcrypt.hash(password, 10);
                    db.query(
                        "INSERT INTO Users (name, email, password, role, student_id) VALUES (?, ?, ?, ?, ?)",
                        [name, email, hashedPassword, 'student', student_id],
                        (err4) => {
                            if (err4) return res.status(500).json({ message: "Something went wrong" });
                            res.json({ message: "Account created successfully" });
                        }
                    );
                });
            });
        } else {
            // student_id nahi diya — teacher signup kar raha hai (role manually SQL se set hoga baad mein)
            const hashedPassword = await bcrypt.hash(password, 10);
            db.query(
                "INSERT INTO Users (name, email, password) VALUES (?, ?, ?)",
                [name, email, hashedPassword],
                (err2) => {
                    if (err2) return res.status(500).json({ message: "Something went wrong" });
                    res.json({ message: "Account created successfully" });
                }
            );
        }
    });
});

// Login — sirf database check
app.post("/auth/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(400).json({ message: "Email and password required" });

    db.query("SELECT * FROM Users WHERE email = ?", [email], async (err, result) => {
        if (err) return res.status(500).json({ message: err.message });

        if (result.length === 0)
            return res.status(401).json({ message: "Invalid email or password" });

        const user = result[0];

       const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(401).json({ message: "Invalid email or password" });

        const userData = { id: user.id, name: user.name, email: user.email, role: user.role, student_id: user.student_id };
        const token = jwt.sign(userData, JWT_SECRET, { expiresIn: "24h" });
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
    res.json({ message: "Logged out successfully" });
});

// ═══════════════════════════════════════════════════════════════════
// STUDENTS
// ═══════════════════════════════════════════════════════════════════

app.get("/students", requireAuth, (req, res) => {
    if (req.user.role === 'teacher') {
        // Teacher ko sabka data milega
        db.query("SELECT * FROM Students", (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(result);
        });
    } else {
        // Student ko sirf apna record milega
        db.query("SELECT * FROM Students WHERE student_id = ?", [req.user.student_id], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(result);
        });
    }
});

app.post("/students", requireAuth, requireTeacher, async (req, res) => {
    const { first_name, last_name, email, enrollment_date } = req.body;

    if (!first_name || !last_name || !email || !enrollment_date) {
        return res.status(400).json({ message: "Please fill all fields" });
    }

    db.query(
        "INSERT INTO Students(first_name, last_name, email, enrollment_date) VALUES (?, ?, ?, ?)",
        [first_name, last_name, email, enrollment_date],
        (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: "This email is already used by another student" });
                }
                return res.status(500).json({ message: "Something went wrong" });
            }

            const newStudentId = result.insertId;

            res.json({
                message: `Student added successfully. Student ID: #${newStudentId} — ask them to sign up using this ID.`,
                newStudentId
            });
        }
    );
});

// app.post("/students", requireAuth, requireTeacher, async (req, res) => {
//     const { first_name, last_name, email, enrollment_date } = req.body;   // student_id nahi liya ab

//     if (!first_name || !last_name || !email || !enrollment_date) {
//         return res.status(400).json({ message: "Please fill all fields" });
//     }

//     db.query(
//         "INSERT INTO Students(first_name, last_name, email, enrollment_date) VALUES (?, ?, ?, ?)",
//         [first_name, last_name, email, enrollment_date],
//         async (err, result) => {
//             if (err) {
//                 if (err.code === 'ER_DUP_ENTRY') {
//                     return res.status(409).json({ message: "This email is already used by another student" });
//                 }
//                 return res.status(500).json({ message: "Something went wrong" });
//             }

//             const newStudentId = result.insertId;   // MySQL ne jo naya ID diya
//             const defaultPassword = `student${newStudentId}`;
//             const hashedPassword = await bcrypt.hash(defaultPassword, 10);

//             db.query(
//                 "INSERT INTO Users (name, email, password, role, student_id) VALUES (?, ?, ?, ?, ?)",
//                 [`${first_name} ${last_name}`, email, hashedPassword, 'student', newStudentId],
//                 (err2) => {
//                     if (err2) {
//                         return res.json({ 
//                             message: `Student added (ID: ${newStudentId}), but login creation failed`, 
//                             newStudentId 
//                         });
//                     }
//                     res.json({ 
//                         message: "Student Added Successfully. Login credentials created.",
//                         newStudentId,
//                         loginEmail: email,
//                         loginPassword: defaultPassword
//                     });
//                 }
//             );
//         }
//     );
// });
app.put("/students/bulk", requireAuth, requireTeacher, (req, res) => {
  const { ids, first_name, last_name, email, enrollment_date } = req.body;

  // 1. Validate that an array of student IDs is provided
  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: "Please provide an array of student IDs" });
  }

  // 2. Build SET fields dynamically based on fields sent in req.body
  const fields = [];
  const values = [];

  if (first_name) { fields.push("first_name = ?"); values.push(first_name); }
  if (last_name)  { fields.push("last_name = ?");  values.push(last_name);  }
  if (email)      { fields.push("email = ?");      values.push(email);      }
  if (enrollment_date) { fields.push("enrollment_date = ?"); values.push(enrollment_date); }

  // 3. Ensure at least one field was provided to update
  if (fields.length === 0) {
    return res.status(400).json({ error: "Please provide at least one field to update" });
  }

  // 4. Generate dynamic placeholders for the WHERE clause (?, ?, ...)
  const placeholders = ids.map(() => "?").join(",");

  // 5. Construct SQL query string dynamically
  const sql = `UPDATE Students SET ${fields.join(", ")} WHERE student_id IN (${placeholders})`;

  // 6. Merge parameter values: [field_values, ...ids]
  const params = [...values, ...ids];

  // 7. Execute query using callback pattern
  db.query(sql, params, (err, result) => {
    if (err) return res.status(500).json(err);

    res.json({
      message: `Successfully updated ${result.affectedRows} student(s)`,
      affectedRows: result.affectedRows
    });
  });
});


app.delete("/students/bulk", requireAuth, requireTeacher, (req, res) => {

    const { ids } = req.body;

    if (
        !Array.isArray(ids) ||
        ids.length === 0 ||
        !ids.every(id => Number.isInteger(Number(id)))
    ) {
        return res.status(400).json({
            message: "ids must be a non-empty array of numbers"
        });
    }

    const placeholders = ids.map(() => "?").join(",");

    const enrollmentSQL =
        `DELETE FROM Enrollments
         WHERE student_id IN (${placeholders})`;

    db.query(enrollmentSQL, ids, (err) => {

        if (err) {
            return res.status(500).json({
                error: err.message
            });
        }

        const studentSQL =
            `DELETE FROM Students
             WHERE student_id IN (${placeholders})`;

        db.query(studentSQL, ids, (err, result) => {

            if (err) {
                return res.status(500).json({
                    error: err.message
                });
            }

            res.json({
                message: "Students deleted successfully",
                deletedCount: result.affectedRows
            });
        });
    });
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

app.post("/courses", requireAuth, requireTeacher, (req, res) => {
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

app.put("/courses/bulk", requireAuth, requireTeacher, (req, res) => {
  const { ids, course_name, instructor, credits } = req.body;

  // 1. Validate that an array of course IDs is provided
  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: "Please provide an array of course IDs" });
  }

  // 2. Build SET fields dynamically based on fields sent in req.body
  const fields = [];
  const values = [];

  if (course_name) { fields.push("course_name = ?"); values.push(course_name); }
  if (instructor)  { fields.push("instructor = ?");  values.push(instructor);  }
  if (credits)      { fields.push("credits = ?");      values.push(credits);      }

  // 3. Ensure at least one field was provided to update
  if (fields.length === 0) {
    return res.status(400).json({ error: "Please provide at least one field to update" });
  }

  // 4. Generate dynamic placeholders for the WHERE clause (?, ?, ...)
  const placeholders = ids.map(() => "?").join(",");

  // 5. Construct SQL query string dynamically
  const sql = `UPDATE Courses SET ${fields.join(", ")} WHERE course_id IN (${placeholders})`;

  // 6. Merge parameter values: [field_values, ...ids]
  const params = [...values, ...ids];

  // 7. Execute query using callback pattern
  db.query(sql, params, (err, result) => {
    if (err) return res.status(500).json(err);

    res.json({
      message: `Successfully updated ${result.affectedRows} course(s)`,
      affectedRows: result.affectedRows
    });
  });
});


app.delete("/courses/bulk", requireAuth, requireTeacher, (req, res) => {

    const { ids } = req.body;

    if (
        !Array.isArray(ids) ||
        ids.length === 0 ||
        !ids.every(id => Number.isInteger(Number(id)))
    ) {
        return res.status(400).json({
            message: "ids must be a non-empty array of numbers"
        });
    }

    const placeholders = ids.map(() => "?").join(",");

    const enrollmentSQL =
        `DELETE FROM Enrollments
         WHERE course_id IN (${placeholders})`;

    db.query(enrollmentSQL, ids, (err) => {

        if (err) {
            return res.status(500).json({
                error: err.message
            });
        }

        const courseSQL =
            `DELETE FROM Courses
             WHERE course_id IN (${placeholders})`;

        db.query(courseSQL, ids, (err, result) => {

            if (err) {
                return res.status(500).json({
                    error: err.message
                });
            }

            res.json({
                message: "Courses deleted successfully",
                deletedCount: result.affectedRows
            });
        });
    });
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

app.post("/enrollments", requireAuth, requireTeacher, (req, res) => {
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

app.put("/enrollments/bulk", requireAuth, requireTeacher, (req, res) => {
  const { ids, student_id, course_id, enrollment_date, grade } = req.body;

  // 1. Validate that an array of enrollment IDs is provided
  if (!ids || !Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: "Please provide an array of enrollment IDs" });
  }

  // 2. Build SET fields dynamically based on fields sent in req.body
  const fields = [];
  const values = [];

  if (student_id) { fields.push("student_id = ?"); values.push(student_id); }
  if (course_id)   { fields.push("course_id = ?");   values.push(course_id);   }
  if (enrollment_date) { fields.push("enrollment_date = ?"); values.push(enrollment_date); }
  if (grade)       { fields.push("grade = ?"); values.push(grade); }

  // 3. Ensure at least one field was provided to update
  if (fields.length === 0) {
    return res.status(400).json({ error: "Please provide at least one field to update" });
  }

  // 4. Generate dynamic placeholders for the WHERE clause (?, ?, ...)
  const placeholders = ids.map(() => "?").join(",");

  // 5. Construct SQL query string dynamically
  const sql = `UPDATE Enrollments SET ${fields.join(", ")} WHERE enrollment_id IN (${placeholders})`;

  // 6. Merge parameter values: [field_values, ...ids]
  const params = [...values, ...ids];

  // 7. Execute query using callback pattern
  db.query(sql, params, (err, result) => {
    if (err) return res.status(500).json(err);

    res.json({
      message: `Successfully updated ${result.affectedRows} enrollment(s)`,
      affectedRows: result.affectedRows
    });
  });
});

app.delete("/enrollments/bulk", requireAuth, requireTeacher, (req, res) => {
    
        const { ids } = req.body;

        if (!Array.isArray(ids) || ids.length === 0) {
            return res.status(400).json({
                error: "No enrollment IDs provided"
            });
        }

        const placeholders = ids.map(() => "?").join(",");
        db.query(
        `DELETE FROM enrollments WHERE enrollment_id IN (${placeholders})`,
        ids,
        (err, result) => {
            if (err){
                return res.status(500).json({
                    error: err.message
                });
            }

            res.json({
                message: "Enrollments deleted successfully",
                deletedCount: result.affectedRows
            });
        }
    );

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