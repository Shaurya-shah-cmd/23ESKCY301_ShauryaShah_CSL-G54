# Suggested test cases for the report

Perform these tests only on your own machine / isolated lab.

| Test ID | Test | Expected result |
|---|---|---|
| TC-01 | Login with `student` / `ChangeMe123!` | Login successful |
| TC-02 | Login with an incorrect password | Authentication failed |
| TC-03 | Run `LIST` when server folder is empty | Empty file list |
| TC-04 | Upload a small text file | Upload completed; file appears in `server_files/` |
| TC-05 | Run `LIST` after upload | Uploaded file is listed |
| TC-06 | Download the uploaded file | File appears in `downloads/` |
| TC-07 | Compare original and downloaded file | Files should be identical |
| TC-08 | Download a missing filename | File not found message |
| TC-09 | Try a path such as `../secret.txt` | Request rejected |
| TC-10 | Inspect `audit.log` | Login and file operations are recorded |

## Screenshots to capture
1. Certificate generation completed.
2. Server running and listening.
3. Successful client login.
4. LIST output.
5. UPLOAD success and server_files folder.
6. DOWNLOAD success and downloads folder.
7. Wrong-password login failure.
8. Audit log showing operations.

Do not fabricate screenshots. Capture the actual output from your own run.
