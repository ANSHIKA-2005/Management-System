A full-stack Student Management System built with Node.js, Express, MySQL, and vanilla JavaScript.<br>
Supports role-based access control so teachers and students see different views of the same data.

**Features**

- Authentication — JWT-based stateless authentication with bcrypt password hashing <br>
- Role-Based Access Control (RBAC) — Teachers can create/edit/delete records; students can only view their own data<br>
- Students, Courses, Enrollments management — Full CRUD with bulk edit/delete support <br>
- Dashboard — Live stats and a course popularity chart (Chart.js) <br>
- Search & Lookup — Look up a student's courses, a course's students, or a specific student-course pairing <br>
- Excel export — Export students, courses, or enrollments to .xlsx (SheetJS) <br>
- Pagination — Client-side pagination on all data tables <br>

**Tech Stack**

- Backend : Node.js, Express
- Database :	MySQL (mysql2)
- Auth : JWT (jsonwebtoken), bcrypt for password hashing
- Frontend :	HTML, CSS, vanilla JavaScript

**How Roles Work**
- Teacher — Full access: add/edit/delete students, courses, and enrollments. Can view all records.
- Student — View-only access, and only to their own record. A student's account is linked to their academic record via student_id, which is set at sign-up and validated against the Students table.
