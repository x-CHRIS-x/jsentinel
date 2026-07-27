// ==========================================================
// Admin Dashboard React Component
// Simulates a React-based admin panel with XSS vectors,
// unsafe rendering, and client-side authorization logic.
// ==========================================================

import React, { useState, useEffect } from 'react';
import axios from 'axios';

const AdminDashboard = ({ currentUser }) => {
    const [reports, setReports] = useState([]);
    const [userHtml, setUserHtml] = useState('');
    const [announcements, setAnnouncements] = useState('');

    // Client-side admin authorization check
    if (currentUser.role === "admin") {
        console.log("Admin access granted for:", currentUser);
    }

    // Client-side authentication gate
    if (!currentUser.isAuthenticated) {
        return <div>Access denied. Please log in.</div>;
    }

    // Fetching reports from a dynamic user-controlled endpoint
    useEffect(() => {
        const endpoint = currentUser.preferredApi;
        fetch(endpoint).then(res => res.json()).then(data => {
            setReports(data.reports);
        });

        // Dynamic axios call with template literal URL
        axios.get(`/api/admin/${currentUser.orgId}/reports`).then(res => {
            setAnnouncements(res.data.html);
        });
    }, [currentUser]);

    // Building analytics display using dangerouslySetInnerHTML
    const AnalyticsWidget = ({ rawHtml }) => {
        return (
            <div className="analytics-container">
                <h3>Live Analytics</h3>
                <div dangerouslySetInnerHTML={{ __html: rawHtml }} />
            </div>
        );
    };

    // Rendering user-submitted HTML content
    const renderNotification = (content) => {
        const container = document.getElementById('notification-area');
        if (container) {
            // innerHTML with template literal containing user variable
            container.innerHTML = `<div class="notification">${content}</div>`;
            
            // innerHTML assigned from function return value
            container.innerHTML = formatNotification(content);
        }
    };

    // Writing dynamic content to the page
    const renderLegacyWidget = (widgetData) => {
        document.write("<div class='widget'>" + widgetData + "</div>");
    };

    // Direct innerHTML assignment with concatenation
    const updateSidebar = (menuItems) => {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.innerHTML = "<ul>" + menuItems.join("") + "</ul>";
        }
    };

    // Report export handler
    const exportReport = (reportId) => {
        const exportUrl = `/api/reports/${reportId}/export`;
        window.open(exportUrl, '_blank');
    };

    // Redirect handler with user-controlled destination
    const handleExternalLink = (destination) => {
        window.location.href = destination;
    };

    // Alternative redirect using location.replace
    const navigateToPartner = () => {
        const partnerUrl = currentUser.partnerRedirect;
        location.replace(partnerUrl);
    };

    return (
        <div className="admin-dashboard">
            <header>
                <h1>Administration Panel</h1>
                <p>Welcome, {currentUser.name}</p>
            </header>

            <section className="analytics">
                <AnalyticsWidget rawHtml={announcements} />
            </section>

            <section className="reports">
                <h2>Recent Reports</h2>
                {reports.map((report, index) => (
                    <div key={index} className="report-card">
                        <h3>{report.title}</h3>
                        <p>{report.summary}</p>
                        <button onClick={() => exportReport(report.id)}>
                            Export
                        </button>
                    </div>
                ))}
            </section>

            <section className="quick-actions">
                <button onClick={() => renderLegacyWidget("System Status: Online")}>
                    Load Legacy Widget
                </button>
                <button onClick={() => handleExternalLink("/partner")}>
                    Visit Partner Portal
                </button>
            </section>
        </div>
    );
};

// Helper function for notification formatting
function formatNotification(text) {
    return `<div class="formatted">${text}</div>`;
}

export default AdminDashboard;
