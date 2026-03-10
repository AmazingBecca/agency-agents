# AI Agent Tool Integration System - Complete Technical Specification

## OVERVIEW

**Total Tools:** 58 active tools across 6 connections + built-in tools  
**Connections:** Gmail, Google Drive (x2), Shortwave, Gemini API, Computer Use  
**Account:** becca@beccatravis.com  

---

## SECTION 1: GMAIL TOOLS (17 tools)
**Connection ID:** `conn_dz9f47erg2zqwpkjgken`

### gmail_search_threads
Search emails using Gmail query syntax.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| query | string | Yes | `"from:karen@* subject:evidence newer_than:7d"` |
| readMask | array | No | `["date", "participants", "subject", "bodyFull"]` |
| maxResults | integer | No | `50` |
| pageToken | string | No | `"abc123"` |
| includeSpamTrash | boolean | No | `false` |

```python
# Search for recent emails from Karen
result = gmail_search_threads(
    query="from:karen@* newer_than:7d",
    readMask=["date", "participants", "subject", "bodySnippet"],
    maxResults=25
)
```

### gmail_get_threads
Get specific threads by ID.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| threadIds | array | Yes | `["17a2b3c4d5e6f7g8"]` |
| readMask | array | No | `["bodyFull", "attachments"]` |

```python
# Get full content of specific threads
threads = gmail_get_threads(
    threadIds=["17a2b3c4d5e6f7g8", "9h8g7f6e5d4c3b2a"],
    readMask=["date", "participants", "subject", "bodyFull", "attachments"]
)
```

### gmail_get_messages
Get specific messages by ID.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| messageIds | array | Yes | `["msg123", "msg456"]` |
| readMask | array | No | `["bodyFull"]` |

### gmail_list_drafts
List all draft emails.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| maxResults | integer | No | `20` |
| query | string | No | `"subject:report"` |

### gmail_get_draft
Get a specific draft by ID.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| draftId | string | Yes | `"r1234567890"` |
| readMask | array | No | `["bodyFull"]` |

### gmail_create_draft
Create a new draft email.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| to | array | Yes | `["recipient@example.com"]` |
| cc | array | No | `["cc@example.com"]` |
| bcc | array | No | `["bcc@example.com"]` |
| subject | string | Yes | `"Case Update"` |
| body | string | No | `"Here is the update..."` (markdown) |
| bodyHtml | string | No | `"<p>HTML content</p>"` |
| attachments | array | No | `["/agent/home/report.pdf"]` |
| replyToMessageId | string | No | `"msg123"` |
| includeSignature | boolean | No | `true` |

```python
# Create a draft reply
draft = gmail_create_draft(
    to=["lawyer@firm.com"],
    subject="Re: Travis Land Case",
    body="# Summary\n\nAttached is the evidence summary.",
    attachments=["/agent/home/evidence_summary.pdf"],
    replyToMessageId="original_msg_id",
    includeSignature=True
)
```

### gmail_update_draft
Update an existing draft.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| draftId | string | Yes | `"r1234567890"` |
| to | array | No | `["new@recipient.com"]` |
| subject | string | No | `"Updated Subject"` |
| body | string | No | `"Updated content"` |

### gmail_send_draft
Send an existing draft immediately.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| draftId | string | Yes | `"r1234567890"` |

### gmail_send_message
Send a new email immediately.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| to | array | Yes | `["recipient@example.com"]` |
| cc | array | No | `["cc@example.com"]` |
| bcc | array | No | `["bcc@example.com"]` |
| subject | string | Yes | `"Urgent: Evidence Found"` |
| body | string | No | `"# Evidence\n\nSee attached."` |
| bodyHtml | string | No | `"<p>HTML</p>"` |
| attachments | array | No | `["/agent/home/file.pdf"]` |
| from | string | No | `"alias@example.com"` |
| replyToMessageId | string | No | `"msg123"` |
| includeSignature | boolean | No | `true` |

```python
# Send urgent email with attachment
gmail_send_message(
    to=["lawyer@firm.com", "karen@example.com"],
    subject="URGENT: New Evidence - Travis Land",
    body="## Critical Finding\n\nSee attached permit analysis.",
    attachments=["/agent/home/permit_analysis.pdf"]
)
```

### gmail_forward_message
Forward a message with attachments.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| messageId | string | Yes | `"msg123"` |
| to | array | Yes | `["forward@example.com"]` |
| cc | array | No | `["cc@example.com"]` |
| bcc | array | No | `["bcc@example.com"]` |
| additionalBody | string | No | `"FYI - see below"` |
| includeAttachments | boolean | No | `true` |

### gmail_download_attachment
Download attachment to agent filesystem.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| messageId | string | Yes | `"msg123"` |
| filename | string | Yes | `"report.pdf"` |
| destinationPath | string | No | `/agent/home/downloads/report.pdf` |

```python
# Download all attachments from a message
gmail_download_attachment(
    messageId="17a2b3c4d5e6f7g8",
    filename="permit_206938.pdf",
    destinationPath="/agent/home/evidence/permit_206938.pdf"
)
```

### gmail_search_labels
Search for Gmail labels.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| filter | string | No | `"travis"` |

### gmail_create_label
Create a new label.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| name | string | Yes | `"Travis Land Case"` |

### gmail_update_label
Rename an existing label.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| labelId | string | Yes | `"Label_123"` |
| name | string | Yes | `"Travis Land - Active"` |

### gmail_delete_label
Delete a label.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| labelId | string | Yes | `"Label_123"` |

### gmail_modify_message_labels
Add or remove labels from messages.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| messageIds | array | Yes | `["msg1", "msg2"]` |
| addLabelIds | array | No | `["Label_123"]` |
| removeLabelIds | array | No | `["INBOX"]` |

```python
# Archive and label messages
gmail_modify_message_labels(
    messageIds=["msg1", "msg2", "msg3"],
    addLabelIds=["Label_TravisLand"],
    removeLabelIds=["INBOX"]
)
```

### setup_gmail_trigger
Create trigger for new emails.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| condition_type | string | Yes | `"new_messages"` or `"label_additions"` |
| filter | string | No | `"from:karen@* -label:SENT"` |
| label_ids | array | No | `["Label_123"]` (for label_additions) |
| title | string | Yes | `"Monitor Karen emails"` |

```python
# Trigger on new emails from Karen
setup_gmail_trigger(
    condition_type="new_messages",
    filter="from:karen@*",
    title="Monitor Karen evidence emails"
)
```

---

## SECTION 2: GOOGLE DRIVE TOOLS (13 tools per connection, 2 connections)
**Connection IDs:** `conn_v6zaz8hw00j3kjfby3j8` (primary), `conn_9wbtcw07xp2tm6ayhv84` (backup)

### google_drive_list_drives
List shared drives.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| limit | integer | No | `50` |
| query | string | No | `"name contains 'Legal'"` |
| paginationToken | string | No | `"token123"` |

### google_drive_search_documents
Search for files in Drive.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| query | string | Yes | `"name contains 'Travis' and mimeType = 'application/pdf'"` |
| corpora | string | No | `"user"`, `"domain"`, `"drive"`, `"allDrives"` |
| driveId | string | No | `"0ABC123"` (required if corpora="drive") |
| limit | integer | No | `50` |
| paginationToken | string | No | `"token123"` |

```python
# Search for Travis Land case files
files = google_drive_search_documents(
    query="name contains 'Travis' and mimeType = 'application/pdf'",
    corpora="allDrives",
    limit=100
)

# Search by modification date
recent = google_drive_search_documents(
    query="modifiedTime > '2026-01-20T00:00:00'",
    corpora="user"
)
```

### google_drive_get_document
Get document by ID (returns markdown for Google Docs).

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| documentId | string | Yes | `"1nsquCw3YCF8BBhElyGAiiIvqcEyTEyOjkV8A6rpZsvg"` |

```python
# Get Travis Land summary document
doc = google_drive_get_document(
    documentId="1nsquCw3YCF8BBhElyGAiiIvqcEyTEyOjkV8A6rpZsvg"
)
```

### google_drive_create_document
Create new Google Doc.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| title | string | Yes | `"Evidence Summary - Jan 2026"` |
| parentFolderId | string | No | `"folder123"` |

### google_drive_append_text_to_document
Append text to existing Doc.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| documentId | string | Yes | `"doc123"` |
| text | string | Yes | `"## New Section\n\nContent here..."` (markdown) |

```python
# Append new findings to case document
google_drive_append_text_to_document(
    documentId="1nsquCw3YCF8BBhElyGAiiIvqcEyTEyOjkV8A6rpZsvg",
    text="\n\n## January 24, 2026 Update\n\nNew evidence discovered in SWFWMD permits..."
)
```

### google_drive_replace_text_in_document
Find and replace text in Doc.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| documentId | string | Yes | `"doc123"` |
| targetText | string | Yes | `"DRAFT - DO NOT DISTRIBUTE"` |
| replacementText | string | Yes | `"FINAL VERSION"` |

### google_drive_create_folder
Create new folder.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| title | string | Yes | `"Travis Land Evidence"` |
| parentFolderId | string | No | `"parent123"` |

### google_drive_create_spreadsheet
Create new Google Sheet.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| title | string | Yes | `"Evidence Tracker"` |
| data | object | No | See below |
| parentFolderId | string | No | `"folder123"` |

```python
# Create evidence tracking spreadsheet
google_drive_create_spreadsheet(
    title="Travis Land Evidence Tracker",
    data={
        "sheets": [{
            "properties": {"title": "Evidence Log"},
            "data": [{
                "rowData": [
                    {"values": [
                        {"userEnteredValue": {"stringValue": "Date"}},
                        {"userEnteredValue": {"stringValue": "Source"}},
                        {"userEnteredValue": {"stringValue": "Finding"}},
                        {"userEnteredValue": {"stringValue": "Importance"}}
                    ]}
                ]
            }]
        }]
    }
)
```

### google_drive_get_spreadsheet
Read spreadsheet data.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| spreadsheetId | string | Yes | `"sheet123"` |
| range | string | No | `"'Sheet1'!A1:D50"` |
| includeEffective | boolean | Yes | `false` |
| includeEntered | boolean | Yes | `true` |

### google_drive_update_spreadsheet
Update spreadsheet cells.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| operation.action | string | Yes | `"update-values"`, `"add-sheet"`, `"update-sheet"` |
| operation.spreadsheetId | string | Yes | `"sheet123"` |
| operation.cellRange | string | Yes* | `"'Sheet1'!A1:B2"` |
| operation.values | array | Yes* | `[["A1", "B1"], ["A2", "B2"]]` |

```python
# Update evidence tracker
google_drive_update_spreadsheet(
    operation={
        "action": "update-values",
        "spreadsheetId": "sheet123",
        "cellRange": "'Evidence Log'!A2:D2",
        "values": [["2026-01-24", "SWFWMD", "Permit #206938 found", "HIGH"]]
    }
)
```

### google_drive_move_file
Move or rename file.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| fileId | string | Yes | `"file123"` |
| targetParentId | string | No | `"newfolder123"` |
| newFileName | string | No | `"renamed_file.pdf"` |

### google_drive_upload_file
Upload file from agent filesystem to Drive.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| filePath | string | Yes | `/agent/home/report.pdf` |
| parentFolderId | string | No | `"folder123"` |
| uploadMimeType | string | No | `"application/vnd.google-apps.document"` |
| fileIdToReplace | string | No | `"existingfile123"` |

```python
# Upload evidence summary to Drive
google_drive_upload_file(
    filePath="/agent/home/evidence_summary.pdf",
    parentFolderId="TravisLandFolder123"
)
```

### google_drive_download_file
Download file from Drive to agent filesystem.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| fileId | string | Yes | `"file123"` |
| destinationPath | string | No | `/agent/home/downloaded.pdf` |
| exportMimeType | string | No | `"application/pdf"` (for Google Docs export) |

```python
# Download permit document
google_drive_download_file(
    fileId="1xB2PxNuhCsyqTFc9nBehjcS-7mQKFi7i",
    destinationPath="/agent/home/evidence/strategic_analysis.pdf"
)
```

---

## SECTION 3: SHORTWAVE TOOLS (10 tools)
**Connection ID:** `conn_wzy9symrex1ks5aczeeh`

### shortwave_get_user_info
Get user info and team IDs.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| (none) | | | |

### shortwave_lookup_thread_id
Convert Gmail ID or URL to Shortwave ID.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| gmail_message_id | string | No* | `"msg123"` |
| shortwave_url | string | No* | `"https://app.shortwave.com/..."` |

*One of these is required.

### shortwave_read_thread
Read thread content.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| shortwave_thread_id | string | Yes | `"sw-thread-123"` |
| read_mask | array | No | `["DATE", "PARTICIPANTS", "BODY_FULL"]` |

### shortwave_create_comment
Add comment to message.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| shortwave_message_id | string | Yes | `"sw-msg-123"` |
| shortwave_team_id | string | Yes | `"team-123"` |
| content_markdown | string | Yes | `"This is important evidence"` |

### shortwave_create_reply_draft
Create reply draft.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| shortwave_thread_id | string | Yes | `"sw-thread-123"` |
| content_markdown | string | Yes | `"Thanks for the update..."` |

### shortwave_create_new_draft
Create new compose draft.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| to | array | No | `["recipient@example.com"]` |
| cc | array | No | `["cc@example.com"]` |
| bcc | array | No | `["bcc@example.com"]` |
| subject | string | Yes | `"New Email"` |
| content_markdown | string | Yes | `"Email body..."` |

### shortwave_edit_draft
Edit existing draft.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| shortwave_draft_id | string | Yes | `"sw-draft-123"` |
| content_markdown | string | Yes | `"Updated content..."` |

### shortwave_list_todos
List all todos.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| (none) | | | |

### shortwave_add_thread_to_todo
Add thread to todo list.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| shortwave_thread_id | string | Yes | `"sw-thread-123"` |
| existing_todo_id | string | No* | `"todo-123"` |
| new_todo_name | string | No* | `"Follow up on evidence"` |

*One of these is required.

### shortwave_list_threads_in_todo
List threads in a todo.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| todo_id | string | Yes | `"todo-123"` |

---

## SECTION 4: GEMINI API (1 tool)
**Connection ID:** `conn_4yf09mc4d2abe99sjs98`

### remote_http_call
Call Gemini API for AI analysis.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| url | string | Yes | `"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"` |
| method | string | Yes | `"POST"` |
| body | string | Yes | JSON request body |
| timeout | integer | No | `120` |
| outputFile | string | No | `/agent/home/response.json` |

```python
# Analyze document with Gemini
remote_http_call(
    url="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
    method="POST",
    body=json.dumps({
        "contents": [{
            "parts": [{
                "text": "Analyze this legal document and extract key findings:\n\n" + document_text
            }]
        }],
        "generationConfig": {
            "maxOutputTokens": 8192,
            "temperature": 0.2
        }
    }),
    timeout=120,
    outputFile="/agent/home/analysis_result.json"
)
```

---

## SECTION 5: COMPUTER USE (4 tools)
**Connection ID:** `conn_q86syv9xy390df3jhnn2`

### computer
Run actions on remote computer screen.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| actions | array | Yes | See action types below |

**Action Types:**
- `type`: Type text. Params: `text`
- `key`: Press key. Params: `keys` (array)
- `enter`: Press enter
- `wait`: Wait. Params: `duration` (seconds)
- `left_click`, `right_click`, `middle_click`, `double_click`, `triple_click`: Click at coordinate
- `mouse_move`: Move mouse. Params: `coordinate` [x, y]
- `scroll`: Scroll. Params: `direction` (up/down/left/right), `amount`
- `screenshot`: Take screenshot
- `get_clipboard`, `set_clipboard`: Clipboard operations

```python
# Take screenshot
computer(actions=[{"action": "screenshot"}])

# Type text and press enter
computer(actions=[
    {"action": "type", "text": "search query"},
    {"action": "enter"}
])

# Click at coordinates
computer(actions=[
    {"action": "left_click", "coordinate": [500, 300]}
])
```

### open_computer_fullscreen
Show computer to user.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| interactive | boolean | Yes | `true` (user control) or `false` (view only) |
| message | string | No | `"Please help me log in"` |

### copy_file_to_computer
Copy file from agent to computer.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| source | string | Yes | `/agent/home/file.pdf` |
| destination | string | Yes | `/Users/becca/Desktop/file.pdf` |

### copy_file_from_computer
Copy file from computer to agent.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| source | string | Yes | `/Users/becca/Documents/evidence.pdf` |
| destination | string | Yes | `/agent/home/evidence.pdf` |

---

## SECTION 6: BUILT-IN TOOLS (no connection needed)

### read_file
Read file or directory contents.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| path | string | Yes | `/agent/home/report.md` |
| start_line | integer | No | `1` |
| end_line | integer | No | `100` |
| pdf_start_page | integer | No | `1` |
| pdf_end_page | integer | No | `5` |
| pdf_format | string | No | `"image"` or `"text"` |

### write_file
Create, edit, or delete files.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| op | string | Yes | `"write"`, `"edit"`, `"delete"` |
| path | string | Yes | `/agent/home/output.md` |
| content | string | No* | `"File content..."` (for write) |
| old_string | string | No* | `"text to find"` (for edit) |
| new_string | string | No* | `"replacement text"` (for edit) |
| replace_all | boolean | No | `false` |

### run_command
Execute shell commands in sandbox.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| command | string | Yes | `"python3 script.py"` |
| timeout | integer | No | `60` (max 300) |

```python
# Run Python analysis
run_command(
    command="""uv run --with pandas,spacy python3 << 'EOF'
import pandas as pd
# Analysis code here
EOF""",
    timeout=120
)
```

### web_search_web
Search the internet.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| query | string | Yes | `"Manatee County water permits"` |
| limit | integer | No | `10` |
| location | string | No | `"Florida"` |
| tbs | string | No | `"qdr:w"` (past week) |

### web_scrape_website
Scrape webpage content.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| url | string | Yes | `"https://example.com/page"` |

### run_agent_memory_sql
Query the persistent SQL database.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| query | string | Yes | `"SELECT * FROM case_findings WHERE case_id = 'travis_land'"` |

### get_agent_db_schema
Get database schema.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| (none) | | | |

### manage_tasks
Create, update, or delete tasks.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| operations | array | Yes | See below |

```python
manage_tasks(operations=[
    {"operation": "add", "title": "Review SWFWMD permits"},
    {"operation": "update", "taskId": "task123", "title": "Updated title"},
    {"operation": "delete", "taskId": "task456"}
])
```

### list_tasks
List current tasks.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| taskIds | array | No | `["task1", "task2"]` |

### send_message
Send email or text to user.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| to | array | Yes | `["owner"]` or `["email@example.com"]` |
| body | string | Yes | `"Message content..."` |
| subject | string | No* | `"Subject line"` (required for email) |

### reply_message
Reply to existing message thread.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| messageId | string | Yes | `"msg123"` |
| body | string | Yes | `"Reply content..."` |

### add_contact_method
Add new contact method (requires verification).

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| type | string | Yes | `"email"` or `"text"` |
| value | string | Yes | `"+12025551234"` or `"email@example.com"` |
| name | string | Yes | `"Becca Phone"` |

### list_contact_methods
List available contact methods.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| (none) | | | |

---

## SECTION 7: TRIGGER TOOLS

### setup_schedule_trigger
Create scheduled trigger.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| title | string | Yes | `"Daily evidence summary"` |
| cron_expression | string | No* | `"0 9 * * *"` (9am daily) |
| start_time | string | No* | `"2026-01-25T09:00:00"` |
| recurring_frequency | string | No | `"P1D"` (daily), `"P1W"` (weekly) |
| expiration_count | integer | No | `10` (stop after 10 runs) |
| expiration_time | string | No | `"2026-02-01T00:00:00"` |

*Use cron_expression OR (start_time + recurring_frequency), not both.

```python
# Daily morning report
setup_schedule_trigger(
    title="Daily evidence summary",
    cron_expression="0 9 * * *"
)

# One-time trigger
setup_schedule_trigger(
    title="January 27 hearing reminder",
    start_time="2026-01-27T07:00:00",
    expiration_count=1
)
```

### setup_webhook_trigger
Create webhook listener.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| title | string | Yes | `"Karen evidence drops"` |

Returns webhook URL that external systems can POST to.

### setup_rss_trigger
Monitor RSS feed.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| feed_url | string | Yes | `"https://example.com/feed.rss"` |
| title | string | Yes | `"Monitor county news"` |

### delete_trigger
Delete a trigger.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| trigger_instance_id | string | Yes | `"trigger_123"` |

### list_triggers
List all active triggers.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| (none) | | | |

### simulate_trigger_event
Test a trigger with sample payload.

| Parameter | Type | Required | Example |
|-----------|------|----------|---------|
| trigger_instance_id | string | Yes | `"trigger_123"` |
| payload | object | Yes | `{"threadId": "17abc"}` |

---

## SECTION 8: DATABASE SCHEMA

```sql
-- Case files tracking
CREATE TABLE case_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    file_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    file_type TEXT,
    source TEXT,
    extracted_text TEXT,
    analysis TEXT,
    importance INTEGER DEFAULT 5,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP
);

-- Email tracking
CREATE TABLE email_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT NOT NULL UNIQUE,
    message_id TEXT,
    subject TEXT,
    sender TEXT,
    recipients TEXT,
    received_at TIMESTAMP,
    processed BOOLEAN DEFAULT FALSE,
    findings TEXT,
    case_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Evidence correlation
CREATE TABLE evidence_correlation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT NOT NULL,
    related_file TEXT NOT NULL,
    relationship_type TEXT,
    confidence REAL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Processing log
CREATE TABLE processing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type TEXT NOT NULL,
    task_id TEXT,
    status TEXT DEFAULT 'pending',
    items_count INTEGER,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT,
    metadata TEXT
);

-- Trigger state
CREATE TABLE trigger_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_id TEXT NOT NULL UNIQUE,
    trigger_type TEXT,
    last_fired TIMESTAMP,
    items_processed INTEGER DEFAULT 0,
    last_item_id TEXT,
    metadata TEXT
);

-- Case findings
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    finding_type TEXT,
    content TEXT NOT NULL,
    source_ref TEXT,
    importance INTEGER DEFAULT 5,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_case_files_case ON case_files(case_id);
CREATE INDEX idx_email_tracking_thread ON email_tracking(thread_id);
CREATE INDEX idx_findings_case ON findings(case_id);
CREATE INDEX idx_processing_log_status ON processing_log(status);
```

---

## SECTION 9: INTEGRATION WORKFLOWS

### Workflow 1: Email Monitoring Pipeline
```
1. setup_gmail_trigger (condition: new_messages, filter: "from:karen@*")
2. [Trigger fires]
3. gmail_get_threads (get full content)
4. gmail_download_attachment (save attachments)
5. run_agent_memory_sql (check if processed)
6. remote_http_call (Gemini analysis)
7. run_agent_memory_sql (store findings)
8. google_drive_append_text_to_document (update case doc)
9. send_message (notify user)
```

### Workflow 2: Document Analysis Pipeline
```
1. google_drive_search_documents (find new files)
2. google_drive_download_file (download to agent)
3. read_file (read content)
4. remote_http_call (Gemini: extract entities, dates, relationships)
5. run_agent_memory_sql (store extracted data)
6. google_drive_append_text_to_document (add summary to master doc)
```

### Workflow 3: Case File Organization
```
1. google_drive_search_documents (query: "Travis" OR "DaCosta")
2. run_command (Python: categorize by case)
3. google_drive_create_folder (create case folders)
4. google_drive_move_file (organize files)
5. google_drive_create_spreadsheet (create index)
6. run_agent_memory_sql (log organization)
```

### Workflow 4: Evidence Correlation
```
1. run_agent_memory_sql (SELECT * FROM case_files)
2. run_command (Python: extract entities from all files)
3. remote_http_call (Gemini: find relationships)
4. run_agent_memory_sql (INSERT INTO evidence_correlation)
5. google_drive_create_document (generate correlation report)
```

### Workflow 5: Automated Reporting
```
1. setup_schedule_trigger (cron: "0 9 * * *")
2. [Trigger fires]
3. gmail_search_threads (past 24 hours)
4. google_drive_search_documents (modified yesterday)
5. run_agent_memory_sql (new findings)
6. run_command (Python: generate report)
7. write_file (save report.md)
8. google_drive_upload_file (upload to Drive)
9. send_message (email summary to user)
```

### Workflow 6: Multi-Case Management
```
1. run_agent_memory_sql (SELECT DISTINCT case_id FROM case_files)
2. For each case:
   a. google_drive_search_documents (case files)
   b. run_agent_memory_sql (case findings)
   c. remote_http_call (Gemini: case status summary)
3. google_drive_create_spreadsheet (master tracker)
4. manage_tasks (create tasks for each case)
```

### Workflow 7: Trigger Automation
```
1. setup_gmail_trigger (new emails)
2. setup_schedule_trigger (daily summary)
3. setup_webhook_trigger (external integrations)
4. list_triggers (verify all active)
5. simulate_trigger_event (test each)
6. run_agent_memory_sql (log trigger state)
```

### Workflow 8: Database State Tracking
```
1. get_agent_db_schema (verify tables exist)
2. run_agent_memory_sql (CREATE TABLE IF NOT EXISTS...)
3. Before processing:
   a. run_agent_memory_sql (SELECT last_processed FROM trigger_state)
4. After processing:
   b. run_agent_memory_sql (UPDATE trigger_state SET last_processed = ?)
5. On error:
   c. run_agent_memory_sql (INSERT INTO processing_log status='error')
```

### Workflow 9: Cross-Platform Sync
```
1. gmail_search_threads (find emails with attachments)
2. gmail_download_attachment (to agent filesystem)
3. google_drive_upload_file (to Drive)
4. shortwave_add_thread_to_todo (track in Shortwave)
5. run_agent_memory_sql (log sync status)
6. send_message (confirm sync complete)
```

### Workflow 10: Backup and Archive
```
1. google_drive_search_documents (all case files)
2. google_drive_download_file (each file to agent)
3. run_command (tar -czf backup.tar.gz /agent/home/case_files/)
4. google_drive_upload_file (backup archive to Drive)
5. gmail_send_message (email backup confirmation)
6. run_agent_memory_sql (log backup timestamp)
```

---

## SECTION 10: PYTHON CODE EXAMPLES

### Example 1: Email Extraction Workflow
```python
import json

# Search for relevant emails
result = gmail_search_threads(
    query="from:karen@* newer_than:7d has:attachment",
    readMask=["date", "participants", "subject", "bodyFull", "attachments"],
    maxResults=50
)

# Process each thread
for thread in result['threads']:
    thread_id = thread['id']
    
    # Check if already processed
    check = run_agent_memory_sql(
        query=f"SELECT id FROM email_tracking WHERE thread_id = '{thread_id}'"
    )
    
    if check['rows']:
        continue  # Skip already processed
    
    # Download attachments
    for msg in thread['messages']:
        if 'attachments' in msg:
            for att in msg['attachments']:
                gmail_download_attachment(
                    messageId=msg['id'],
                    filename=att['filename'],
                    destinationPath=f"/agent/home/evidence/{att['filename']}"
                )
    
    # Log as processed
    run_agent_memory_sql(
        query=f"""
        INSERT INTO email_tracking (thread_id, subject, sender, processed)
        VALUES ('{thread_id}', '{thread['subject']}', '{thread['from']}', TRUE)
        """
    )
```

### Example 2: Document Analysis with Gemini
```python
import json

# Read document
content = read_file(path="/agent/home/evidence/permit_206938.pdf", pdf_format="text")

# Analyze with Gemini
response = remote_http_call(
    url="https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
    method="POST",
    body=json.dumps({
        "contents": [{
            "parts": [{
                "text": f"""Analyze this legal document and extract:
1. Key dates
2. Named entities (people, companies, properties)
3. Legal claims or violations
4. Evidence of coordination

Document:
{content}
"""
            }]
        }],
        "generationConfig": {
            "maxOutputTokens": 4096,
            "temperature": 0.1
        }
    }),
    outputFile="/agent/home/analysis_result.json"
)

# Parse and store results
with open('/agent/home/analysis_result.json') as f:
    analysis = json.load(f)
    
findings = analysis['candidates'][0]['content']['parts'][0]['text']

run_agent_memory_sql(
    query=f"""
    INSERT INTO findings (case_id, finding_type, content, source_ref, importance)
    VALUES ('travis_land', 'document_analysis', '{findings}', 'permit_206938.pdf', 8)
    """
)
```

### Example 3: Database Operations
```python
# Initialize database schema
run_agent_memory_sql(query="""
CREATE TABLE IF NOT EXISTS case_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    file_id TEXT NOT NULL UNIQUE,
    filename TEXT NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# Insert new file
run_agent_memory_sql(query="""
INSERT OR IGNORE INTO case_files (case_id, file_id, filename)
VALUES ('travis_land', 'drive_abc123', 'Strategic_Analysis.pdf')
""")

# Query unprocessed files
result = run_agent_memory_sql(query="""
SELECT file_id, filename FROM case_files
WHERE case_id = 'travis_land' AND processed = FALSE
ORDER BY created_at DESC
LIMIT 10
""")

# Update processing status
run_agent_memory_sql(query="""
UPDATE case_files SET processed = TRUE
WHERE file_id = 'drive_abc123'
""")

# Get statistics
stats = run_agent_memory_sql(query="""
SELECT 
    case_id,
    COUNT(*) as total_files,
    SUM(CASE WHEN processed THEN 1 ELSE 0 END) as processed_files
FROM case_files
GROUP BY case_id
""")
```

### Example 4: Trigger Handling
```python
# When trigger fires, payload contains thread_id
def handle_gmail_trigger(payload):
    thread_id = payload['threadId']
    
    # Get full thread content
    thread = gmail_get_threads(
        threadIds=[thread_id],
        readMask=["date", "participants", "subject", "bodyFull", "attachments"]
    )
    
    # Check if relevant to case
    subject = thread['threads'][0]['subject'].lower()
    relevant_keywords = ['travis', 'falkner', 'permit', 'evidence', 'county']
    
    if any(kw in subject for kw in relevant_keywords):
        # Process as case email
        gmail_modify_message_labels(
            messageIds=[thread['threads'][0]['messages'][0]['id']],
            addLabelIds=["Label_TravisLand"]
        )
        
        # Notify user
        send_message(
            to=["owner"],
            subject="New Case Email Detected",
            body=f"Relevant email received: {subject}"
        )
        
        # Log to database
        run_agent_memory_sql(query=f"""
        INSERT INTO email_tracking (thread_id, subject, case_id, processed)
        VALUES ('{thread_id}', '{subject}', 'travis_land', TRUE)
        """)
```

### Example 5: File Sync Between Systems
```python
# Sync Gmail attachments to Google Drive
def sync_email_attachments_to_drive():
    # Search for unsynced emails with attachments
    result = gmail_search_threads(
        query="has:attachment newer_than:1d -label:synced",
        readMask=["date", "subject", "attachments"],
        maxResults=20
    )
    
    synced_count = 0
    
    for thread in result.get('threads', []):
        for msg in thread.get('messages', []):
            if 'attachments' not in msg:
                continue
                
            for att in msg['attachments']:
                # Download to agent
                local_path = f"/agent/home/sync_temp/{att['filename']}"
                gmail_download_attachment(
                    messageId=msg['id'],
                    filename=att['filename'],
                    destinationPath=local_path
                )
                
                # Upload to Drive
                google_drive_upload_file(
                    filePath=local_path,
                    parentFolderId="TravisLandEvidenceFolder"
                )
                
                synced_count += 1
        
        # Mark as synced
        gmail_modify_message_labels(
            messageIds=[msg['id'] for msg in thread['messages']],
            addLabelIds=["Label_Synced"]
        )
    
    # Log sync operation
    run_agent_memory_sql(query=f"""
    INSERT INTO processing_log (task_type, status, items_count, completed_at)
    VALUES ('email_drive_sync', 'completed', {synced_count}, CURRENT_TIMESTAMP)
    """)
    
    return synced_count
```

---

## SECTION 11: DEPLOYMENT CHECKLIST

### Phase 1: Initial Setup
- [ ] 1. Verify all connections are active (6 total)
- [ ] 2. Test each connection with simple query
- [ ] 3. Create database schema (run SQL CREATE statements)
- [ ] 4. Verify database tables exist

### Phase 2: Gmail Configuration
- [ ] 5. Search for existing labels
- [ ] 6. Create case-specific labels (Travis Land, DaCosta)
- [ ] 7. Set up Gmail trigger for new messages
- [ ] 8. Test trigger with simulate_trigger_event

### Phase 3: Drive Organization
- [ ] 9. List existing case files
- [ ] 10. Create case folder structure
- [ ] 11. Move files to appropriate folders
- [ ] 12. Create case index spreadsheet

### Phase 4: Automation Setup
- [ ] 13. Set up daily summary trigger (9am)
- [ ] 14. Set up email monitoring trigger
- [ ] 15. Test all triggers
- [ ] 16. Verify database state tracking

### Phase 5: Evidence Processing
- [ ] 17. Download key documents to agent
- [ ] 18. Run Gemini analysis on each
- [ ] 19. Store findings in database
- [ ] 20. Update case documents with findings

### Phase 6: Verification
- [ ] 21. Run full workflow test
- [ ] 22. Verify all triggers fire correctly
- [ ] 23. Check database contains expected data
- [ ] 24. Send test notification to user

---

## ANCHORS (Quick Reference)

**Connection IDs:**
- Gmail: `conn_dz9f47erg2zqwpkjgken`
- Drive (primary): `conn_v6zaz8hw00j3kjfby3j8`
- Drive (backup): `conn_9wbtcw07xp2tm6ayhv84`
- Shortwave: `conn_wzy9symrex1ks5aczeeh`
- Gemini: `conn_4yf09mc4d2abe99sjs98`
- Computer: `conn_q86syv9xy390df3jhnn2`

**Key Document IDs:**
- Travis Land Summary: `1nsquCw3YCF8BBhElyGAiiIvqcEyTEyOjkV8A6rpZsvg`
- Strategic Analysis: `18UwKxkab_qlgtKobgOgGV5qIXjQTRLS0FApPCzQHfaI`
- Strategic Analysis PDF: `1xB2PxNuhCsyqTFc9nBehjcS-7mQKFi7i`
- Case Summary PDF: `10TGsO_7zoMPGGC5qZUl-ZRgVieoi0ds9`

**Database Tables:**
- `case_files`: File tracking
- `email_tracking`: Email processing log
- `evidence_correlation`: Relationship mapping
- `processing_log`: Task execution log
- `trigger_state`: Trigger state persistence
- `findings`: Case findings storage

**Case IDs:**
- Travis Land: `travis_land`
- DaCosta/GEICO: `dacosta_geico`
- Eco Sport: `6734`
- OEM Fraud: `8585`

---

*Document generated: January 24, 2026*
*Total tools: 58*
*Word count: 4,500+*
