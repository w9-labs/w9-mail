'use client'

import Link from 'next/link'
import { useSession } from '../../lib/session'
import Nav from '../components/Nav'

export default function DocsPage() {
  const { session } = useSession()
  const isNormalUser = session && session.role === 'user'

  return (
    <main className="app">
      <header className="header">
        <h1>W9 Mail / API Sheet</h1>
        <p>Monochrome reference for the HTTP surface.</p>
      </header>

      <Nav active="docs" />

      {isNormalUser && (
        <section className="box" style={{ backgroundColor: '#1a1a1a', border: '2px solid #666' }}>
          <p style={{ margin: 0, color: '#fff' }}>
            <strong>Note:</strong> As a normal user, you can read this API documentation, but you cannot use the API endpoints. Only dev users and admins have access to the API.
          </p>
          <p style={{ marginTop: '16px', marginBottom: 0, color: '#fff' }}>
            To apply for Dev user access, send an email to <a href="mailto:hi@w9.nu" style={{ color: '#fff', textDecoration: 'underline' }}>hi@w9.nu</a> with valid reasons for your application.
          </p>
        </section>
      )}

      <>
          <section className="box">
            <h2 className="section-title">Base URL</h2>
            <code>http://localhost:8080/api</code>
            <p>Replace host with your deployed domain (e.g., https://w9.nu/api).</p>
          </section>

          <section className="box">
            <h2 className="section-title">Endpoints</h2>

            <article>
              <h3>POST /api/auth/login</h3>
              <p>Exchange email + password for a JWT. Required before every other call.</p>
              <pre>{`REQUEST:
{
  "email": "user@domain.com",
  "password": "string"
}

RESPONSE:
{
  "token": "jwt",
  "role": "user|dev|admin",
  "mustChangePassword": false
}`}</pre>
            </article>

            <article>
              <h3>POST /api/auth/change-password</h3>
              <p>Forces default admin to rotate secrets on first login.</p>
              <pre>{`HEADERS:
Authorization: Bearer &lt;jwt&gt;

BODY:
{
  "currentPassword": "string",
  "newPassword": "string"
}`}</pre>
            </article>

            <article>
              <h3>POST /api/auth/signup</h3>
              <p>Register a normal user and trigger the verification email.</p>
              <pre>{`REQUEST:
{
  "email": "user@domain.com",
  "password": "string (>=8 chars)"
}

RESPONSE:
{
  "status": "pending",
  "message": "Check your inbox for a verification link."
}`}</pre>
            </article>

            <article>
              <h3>POST /api/auth/signup/verify</h3>
              <p>Confirm the token emailed during signup.</p>
              <pre>{`REQUEST:
{
  "token": "uuid-from-email"
}

RESPONSE:
{
  "status": "verified",
  "message": "Account verified. You can sign in now."
}`}</pre>
            </article>

            <article>
              <h3>POST /api/auth/password-reset</h3>
              <p>Send a reset link via the default sender. Hides whether the email exists.</p>
              <pre>{`REQUEST:
{
  "email": "user@domain.com"
}

RESPONSE:
{
  "status": "ok",
  "message": "If the email exists, a reset link was sent."
}`}</pre>
            </article>

            <article>
              <h3>POST /api/auth/password-reset/confirm</h3>
              <p>Consume the reset token and set a new password.</p>
              <pre>{`REQUEST:
{
  "token": "uuid",
  "newPassword": "string"
}

RESPONSE:
{
  "status": "success",
  "message": "Password updated. You can sign in now."
}`}</pre>
            </article>

            <article>
              <h3>GET /api/accounts</h3>
              <p>List all sender profiles (auth required). Normal users only see status, admins can mutate.</p>
              <pre>{`HEADERS:
Authorization: Bearer &lt;jwt&gt;

RESPONSE:
[
  {
    "id": "uuid",
    "email": "ops@domain.com",
    "displayName": "Ops Bot",
    "isActive": true
  }
]`}</pre>
            </article>

            <article>
              <h3>POST /api/accounts</h3>
              <p>Create a new sender (stores password for SMTP authentication).</p>
              <pre>{`HEADERS:
Authorization: Bearer &lt;admin jwt&gt;

REQUEST:
{
  "email": "string",
  "displayName": "string",
  "password": "string",
  "isActive": boolean
}`}</pre>
            </article>

            <article>
              <h3>PATCH /api/accounts/:id</h3>
              <p>Toggle activation and/or rotate password.</p>
              <pre>{`HEADERS:
Authorization: Bearer &lt;admin jwt&gt;

REQUEST:
{
  "isActive": boolean?,
  "password": "string?"
}`}</pre>
            </article>

            <article>
              <h3>POST /api/send</h3>
              <p>Send email using any registered account or alias. Available to user, dev, and admin roles. The <code>from</code> address must match a registered account email or alias email that is active.</p>
              <pre>{`HEADERS:
Authorization: Bearer &lt;user|dev|admin jwt&gt;

REQUEST:
{
  "from": "sender@domain.com",
  "to": "to@domain.com",
  "subject": "string",
  "body": "string",
  "cc": "optional string (comma-separated)",
  "bcc": "optional string (comma-separated)",
  "isHtml": false
}

RESPONSE:
{
  "status": "sent",
  "message": "Email sent successfully"
}

ERROR RESPONSE:
{
  "status": "error",
  "message": "Sender account or alias not found or inactive"
}`}</pre>
              <p><strong>Notes:</strong></p>
              <ul style={{ marginLeft: '20px', marginTop: '8px' }}>
                <li>The <code>from</code> field accepts either a base account email or an alias email. Aliases will send via their associated account credentials.</li>
                <li>Set <code>isHtml</code> to <code>true</code> to send HTML-formatted emails. When <code>false</code> or omitted, emails are sent as plain text.</li>
                <li>Multiple recipients in <code>to</code>, <code>cc</code>, or <code>bcc</code> should be comma-separated.</li>
                <li>The sender account or alias must be active for the email to be sent.</li>
              </ul>
            </article>

            <article>
              <h3>GET /api/users</h3>
              <p>Admin-only snapshot of every auth profile.</p>
            </article>

            <article>
              <h3>POST /api/users</h3>
              <p>Admin-only invite. Defaults to creating a normal user.</p>
            </article>

          <article>
            <h3>PATCH /api/users/:id</h3>
            <p>Admin-only mutation for rotating roles or forcing password resets.</p>
            <pre>{`HEADERS:
Authorization: Bearer &lt;admin jwt&gt;

REQUEST:
{
  "password": "optional string",
  "role": "admin|dev|user?",
  "mustChangePassword": boolean?
}`}</pre>
          </article>

          <article>
            <h3>DELETE /api/users/:id</h3>
            <p>Admin-only removal. Backend blocks deleting the currently authenticated admin.</p>
          </article>

          <article>
            <h3>GET /api/settings/default-sender</h3>
            <p>Admin-only snapshot of the automatic sender used for signup and reset emails.</p>
            <pre>{`RESPONSE:
{
  "senderType": "account|alias",
  "senderId": "uuid",
  "email": "alias@domain.com",
  "displayLabel": "Marketing Bot",
  "viaDisplay": "Ops Bot (ops@domain.com)",
  "isActive": true
}`}</pre>
          </article>

          <article>
            <h3>PUT /api/settings/default-sender</h3>
            <p>Admin-only setter. Only active accounts or aliases are accepted.</p>
            <pre>{`REQUEST:
{
  "senderType": "account|alias",
  "senderId": "uuid"
}`}</pre>
          </article>

            <article>
              <h3>GET /api/inbox</h3>
              <p>IMAP bridge (placeholder for future work).</p>
              <pre>{`QUERY:
account=sender@domain.com
limit=50
              `}</pre>
            </article>
          </section>
      </>
    </main>
  )
}

