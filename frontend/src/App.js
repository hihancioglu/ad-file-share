import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loggedIn, setLoggedIn] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [userFiles, setUserFiles] = useState([]);
  const [sharedLinks, setSharedLinks] = useState({});
  const [view, setView] = useState('home');
  const [menuOpen, setMenuOpen] = useState(false);
  const [stats, setStats] = useState({ file_count: 0, download_count: 0, download_logs: [] });

  const handleLogin = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append("username", username);
    formData.append("password", password);

    const res = await fetch(`${API_URL}/login`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      setLoggedIn(true);
      setView('home');
      fetchStats();
    } else {
      alert("Giriş başarısız: " + data.error);
    }
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return alert("Dosya seçiniz!");
    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("username", username);

    const res = await fetch(`${API_URL}/upload`, {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      alert("Yükleme başarılı: " + data.filename);
      setSelectedFile(null);
      fetchStats();
    } else {
      alert("Hata: " + data.error);
    }
  };

  const fetchFiles = async () => {
    const formData = new FormData();
    formData.append("username", username);

    const res = await fetch(`${API_URL}/list`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    setUserFiles(data.files || []);
    setSharedLinks({});
  };

  const fetchStats = async () => {
    const formData = new FormData();
    formData.append("username", username);

    const res = await fetch(`${API_URL}/stats`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    setStats(data);
  };

  const handleDownload = async (filename) => {
    const formData = new FormData();
    formData.append("username", username);
    formData.append("filename", filename);

    const res = await fetch(`${API_URL}/download`, {
      method: "POST",
      body: formData
    });

    if (res.ok) {
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
      fetchStats();
    } else {
      alert("İndirme başarısız!");
    }
  };

  const handleDelete = async (filename) => {
    if (!window.confirm(`${filename} silinsin mi?`)) return;
    const formData = new FormData();
    formData.append("username", username);
    formData.append("filename", filename);

    const res = await fetch(`${API_URL}/delete`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      alert("Dosya silindi");
      fetchFiles();
      fetchStats();
    } else {
      alert("Silinemedi: " + data.error);
    }
  };

  const handleShare = async (filename) => {
    const formData = new FormData();
    formData.append("username", username);
    formData.append("filename", filename);

    const res = await fetch(`${API_URL}/share`, {
      method: "POST",
      body: formData
    });
    const data = await res.json();
    if (data.success) {
      setSharedLinks(prev => ({ ...prev, [filename]: `${API_URL}${data.link}` }));
    } else {
      alert("Paylaşım hatası: " + data.error);
    }
  };

  useEffect(() => {
    if (loggedIn && view === 'files') {
      fetchFiles();
    }
    if (loggedIn && view === 'home') {
      fetchStats();
    }
    // eslint-disable-next-line
  }, [view, loggedIn]);

  if (!loggedIn) {
    return (
      <div className="container">
        <h2>AD Girişi</h2>
        <form onSubmit={handleLogin}>
          <input
            placeholder="Kullanıcı adı"
            value={username}
            onChange={e => setUsername(e.target.value)}
            className="text-input"
          /><br />
          <input
            placeholder="Şifre"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            className="text-input"
          /><br />
          <button type="submit" className="btn">Giriş</button>
        </form>
      </div>
    );
  }

  return (
    <div>
      <div className="hamburger" onClick={() => setMenuOpen(!menuOpen)}>☰</div>
      {menuOpen && (
        <div className="menu">
          <button onClick={() => { setView('home'); setMenuOpen(false); }}>Anasayfa</button>
          <button onClick={() => { setView('upload'); setMenuOpen(false); }}>Yükle</button>
          <button onClick={() => { setView('files'); setMenuOpen(false); }}>Dosyalarım</button>
          <button onClick={() => { setLoggedIn(false); setMenuOpen(false); }}>Çıkış</button>
        </div>
      )}

      <div className="container">
        {view === 'home' && (
          <div className="stats">
            <h2>İstatistikler</h2>
            <p>Toplam dosya: {stats.file_count}</p>
            <p>Toplam indirme: {stats.download_count}</p>
            <h3>İndirme Logları:</h3>
            <ul>
              {stats.download_logs && stats.download_logs.map((log, idx) => (
                <li key={idx}>{log.timestamp} - {log.filename}</li>
              ))}
            </ul>
          </div>
        )}

        {view === 'upload' && (
          <div>
            <h2>Dosya Yükle</h2>
            <form onSubmit={handleUpload}>
              <input type="file" onChange={e => setSelectedFile(e.target.files[0])} /><br /><br />
              <button type="submit" className="btn">Yükle</button>
            </form>
          </div>
        )}

        {view === 'files' && (
          <div className="file-section">
            <h2>Dosyalarım</h2>
            <ul>
              {userFiles.map(file => (
                <li key={file} className="file-item">
                  <span className="file-link" onClick={() => handleDownload(file)}>{file}</span>
                  <button onClick={() => handleDelete(file)}>Sil</button>
                  <button onClick={() => handleShare(file)}>Paylaş</button>
                  {sharedLinks[file] && (
                    <a href={sharedLinks[file]} target="_blank" rel="noopener noreferrer">
                      Link
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;

