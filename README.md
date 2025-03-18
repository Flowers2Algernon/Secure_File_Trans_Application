# File Transfer System

## Overview
The file transfer system adopts a frontend-backend separation architecture, supporting efficient and secure file uploading, downloading, and management. A middle-layer caching server is designed to temporarily store files, enhancing transfer speed. The system also integrates Single Sign-On (SSO) to ensure secure and convenient user authentication.

## Technology Stack
- **Frontend**: Developed with JavaScript, using modern frameworks such as **React**, **Vue**, or **Angular** to build an interactive UI for a smooth user experience.
- **Backend**: Developed in **Python**, utilizing the **Django** framework to provide RESTful API services.
- **Cache Server**: Used for temporary file storage to enhance file transfer speed and prevent direct pressure on databases or long-term storage.
- **Authentication**: Integrated **Single Sign-On (SSO)** to ensure login security.

## Key Features
- **File Upload**: Users can upload files via the frontend, which are received by the backend, stored in the cache server, and assigned a unique file link.
- **File Download**: Users can download files via the frontend by retrieving links from the cache server or backend, with support for resumable downloads.
- **Access Control**: SSO authentication ensures users can only access authorized files.
- **Efficient Caching**: Temporary and frequently accessed files are managed to optimize transfer speed and system performance.
- **Logging & Monitoring**: Tracks upload/download logs and monitors API requests to maintain system stability.

## Workflow
### End to Eng Encryption

### File Upload
- Users select a file and submit an upload request.
- The frontend optionally splits the file into chunks and sends it via API to the cache server.
- The backend stores the file and returns a storage path and access link.

### File Download
- Users request file downloads, and the backend verifies access permissions.
- The file is retrieved from the cache server or storage system.
- The file is returned to the user.

### Cache Management
- Temporary files are automatically cleared after a set timeout to reduce storage load.
- Frequently accessed files are cached for long-term access to enhance speed.

---

## License
This project is licensed under the MIT License.

## Contact
For any questions or contributions, please feel free to open an issue or submit a pull request.

