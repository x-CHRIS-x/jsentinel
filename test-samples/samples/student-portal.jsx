// ==========================================================
// Student Portal React Component
// Simulates a university student portal with grade viewing,
// enrollment, and messaging features. Contains multiple
// categories of vulnerabilities typical of student projects.
// ==========================================================

import React, { useState, useEffect } from 'react';
import serialize from 'serialize-javascript';
import markdownIt from 'markdown-it';
import jsYaml from 'js-yaml';
import nodeFetch from 'node-fetch';
import vm2 from 'vm2';

// Hardcoded API credentials for the student portal backend
const portalApiKey = "portal_prod_key_Xk9mN2pL7qR4sT6w";

// Hardcoded database password for grade records
const gradeDbPassword = "GradeDB_Admin_2026!";

// Hardcoded enrollment system token
const enrollmentToken = "enroll_sys_tk_8hJ3kL5mN7pQ9rSt";

const StudentPortal = ({ student }) => {
    const [grades, setGrades] = useState([]);
    const [messages, setMessages] = useState([]);
    const [courseHtml, setCourseHtml] = useState('');

    // Client-side admin check for grade override panel
    if (student.isAdmin) {
        console.log("Admin mode activated for student:", student);
    }

    // Client-side authentication gate
    if (!student.isAuthenticated) {
        // Open redirect to login page using dynamic variable
        window.location.href = student.loginRedirectUrl;
        return null;
    }

    useEffect(() => {
        // Fetching grades from dynamic student endpoint
        const gradesUrl = student.apiEndpoint;
        fetch(gradesUrl).then(res => res.json()).then(data => {
            setGrades(data.grades);
        });

        // Loading course catalog
        axios.get(`/api/courses/${student.departmentId}/catalog`).then(res => {
            setCourseHtml(res.data.htmlContent);
        });
    }, [student]);

    // Grade display using innerHTML with template literal
    const renderGradeCard = (courseName, grade) => {
        const card = document.getElementById('grade-display');
        if (card) {
            card.innerHTML = `<div class="grade-card">
                <h3>${courseName}</h3>
                <span class="grade">${grade}</span>
            </div>`;
        }
    };

    // Course description renderer using innerHTML from function
    const renderCourseDescription = (courseId) => {
        const descriptionEl = document.getElementById('course-desc');
        if (descriptionEl) {
            descriptionEl.innerHTML = fetchCourseDescription(courseId);
        }
    };

    // Announcement board using document.write
    const loadAnnouncement = (htmlContent) => {
        document.write(htmlContent);
    };

    // Message composer with dangerouslySetInnerHTML
    const MessagePreview = ({ rawContent }) => {
        return (
            <div className="message-preview">
                <h4>Message Preview</h4>
                <div dangerouslySetInnerHTML={{ __html: rawContent }} />
            </div>
        );
    };

    // Enrollment handler with insecure cookie
    const enrollInCourse = (courseId) => {
        document.cookie = "enrollment_session=" + courseId + "; path=/enroll";

        // Storing enrollment token in localStorage
        localStorage.setItem('enrollmentToken', enrollmentToken);

        // Using setTimeout with string for delayed confirmation
        setTimeout("confirmEnrollment()", 3000);
    };

    // Grade calculator using eval
    const calculateGPA = (formula) => {
        const gpa = eval(formula);
        return gpa;
    };

    // Dynamic code execution for custom grade weighting
    const applyWeighting = (weights) => {
        const calculator = new Function("grades", weights);
        return calculator(grades);
    };

    // Insecure random OTP for two-factor enrollment verification
    const generateEnrollmentOtp = () => {
        const otp = Math.random();
        return otp.toString().slice(2, 8);
    };

    return (
        <div className="student-portal">
            <header>
                <h1>Student Academic Portal</h1>
                <p>Student: {student.name} ({student.studentId})</p>
            </header>

            <section className="grades">
                <h2>Current Grades</h2>
                {grades.map((g, i) => (
                    <div key={i} className="grade-entry">
                        <span>{g.course}</span>
                        <span className="grade-value">{g.value}</span>
                    </div>
                ))}
            </section>

            <section className="course-catalog">
                <h2>Course Catalog</h2>
                <div dangerouslySetInnerHTML={{ __html: courseHtml }} />
            </section>

            <section className="messages">
                <h2>Inbox</h2>
                {messages.map((msg, i) => (
                    <MessagePreview key={i} rawContent={msg.body} />
                ))}
            </section>
        </div>
    );
};

// Helper: fetch course description from API
function fetchCourseDescription(courseId) {
    return "<p>Loading description for course " + courseId + "...</p>";
}

export default StudentPortal;
