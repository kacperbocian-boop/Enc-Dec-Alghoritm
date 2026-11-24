import { useState } from "react";
import "bootstrap/dist/css/bootstrap.min.css";

const API = "http://localhost:3050/api";
const cryptoAlgorithms = [
  ["chacha20-poly1305", "ChaCha20-Poly1305"],
  ["xchacha20-poly1305", "XChaCha20-Poly1305"],
  ["xsalsa20-poly1305", "XSalsa20-Poly1305"],
  ["aes-256-gcm", "AES-256-GCM"],
  ["aes-256-ccm", "AES-256-CCM"],
  ["aria-256-ccm", "ARIA-256-CCM"],
  ["aria-256-gcm", "ARIA-256-GCM"],
  ["3des-cbc-hmac-sha256", "3DES-CBC + HMAC-SHA256 (legacy)"],
  ["rsa-oaep-2048", "RSA-OAEP-2048 + AES-256-GCM"],
  ["rsa-oaep-3072", "RSA-OAEP-3072 + AES-256-GCM"],
];

const tools = [
  { id: "encode", name: "Encode", symbol: "E" },
  { id: "decode", name: "Decode", symbol: "D" },
  { id: "encrypt", name: "Encrypt", symbol: "S" },
  { id: "decrypt", name: "Decrypt", symbol: "U" },
];

function App() {
  const [mode, setMode] = useState("encode");
  const [type, setType] = useState("base64");
  const [text, setText] = useState("");
  const [key, setKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [wrappedKey, setWrappedKey] = useState("");
  const [nonce, setNonce] = useState("");
  const [authTag, setAuthTag] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [responseData, setResponseData] = useState(null);

  const isCrypto = mode === "encrypt" || mode === "decrypt";
  const isRsa = type.startsWith("rsa-");

  const changeMode = (newMode) => {
    const keepsCryptoState = isCrypto && ["encrypt", "decrypt"].includes(newMode);
    const nextText = mode === "encrypt" && newMode === "decrypt"
      ? responseData?.encrypted || ""
      : "";
    const nextWrappedKey = mode === "encrypt" && newMode === "decrypt"
      ? responseData?.wrappedKey || ""
      : "";
    setMode(newMode);
    setType(
      ["encode", "decode"].includes(newMode)
        ? "base64"
        : keepsCryptoState
          ? type
          : "aes-256-gcm",
    );
    setText(nextText);
    setWrappedKey(nextWrappedKey);
    if (type.startsWith("rsa-") && mode === "encrypt" && newMode === "decrypt" && privateKey) {
      setKey(privateKey);
    }
    if (!keepsCryptoState) {
      setKey("");
      setPrivateKey("");
      setNonce("");
      setAuthTag("");
      setWrappedKey("");
    }
    setResult("");
    setError("");
    setResponseData(null);
  };

  const clear = () => {
    setText("");
    setKey("");
    setPrivateKey("");
    setWrappedKey("");
    setNonce("");
    setAuthTag("");
    setResult("");
    setError("");
    setResponseData(null);
  };

  const generateKey = async () => {
    if (isRsa) {
      setLoading(true);
      setError("");
      try {
        const response = await fetch(`${API}/keypair`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ algorithm: type }),
        }).catch(() => {
          throw new Error("Nie udalo sie polaczyc z API sprawdz czy serwer jest uruchomiony");
        });
        const data = await response.json().catch(() => {
          throw new Error("Serwer zwrocil niepoprawna odpowiedz");
        });
        if (!response.ok) throw new Error(data.error || "Nie udalo sie wygenerowac pary RSA");
        setKey(data.publicKey);
        setPrivateKey(data.privateKey);
      } catch {
        setError("Nie udalo sie wygenerowac pary RSA");
      } finally {
        setLoading(false);
      }
      return;
    }

    const keyBytes = type === "3des-cbc-hmac-sha256"
      ? 56
      : type.startsWith("aes-") || type.startsWith("aria-")
        ? Number(type.split("-")[1]) / 8
        : 32;
    const bytes = crypto.getRandomValues(new Uint8Array(keyBytes));
    const generated = Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    setKey(generated);
  };

  const handleSubmit = async () => {
    if (!text) {
      setError("Najpierw wpisz tekst");
      return;
    }

    if (isCrypto && !key) {
      setError("Wprowadz klucz");
      return;
    }

    setLoading(true);
    setError("");
    setResult("");
    setResponseData(null);

    try {
      let body;

      if (mode === "encode" || mode === "decode") {
        body = { text, type };
      }

      if (mode === "encrypt") {
        body = { text, key, algorithm: type };
      }

      if (mode === "decrypt") {
        body = {
          encrypted: text,
          key,
          nonce,
          authTag,
          wrappedKey: isRsa ? wrappedKey : undefined,
          algorithm: type,
        };
      }

      const response = await fetch(`${API}/${mode}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      }).catch(() => {
        throw new Error("Nie udalo sie polaczyc z API sprawdz czy serwer jest uruchomiony");
      });

      const data = await response.json().catch(() => {
        throw new Error("Serwer zwrocil niepoprawna odpowiedz");
      });

      if (!response.ok) {
        throw new Error(
          data.error || "Sprawdz czy serwer jest uruchomiony",
        );
      }

      setResponseData(data);

      const output =
        data.encoded ?? data.decoded ?? data.decrypted ?? data.encrypted ?? "";

      setResult(
        typeof output === "string" ? output : JSON.stringify(output, null, 2),
      );

      if (data.nonce) setNonce(data.nonce);
      if (data.authTag) setAuthTag(data.authTag);
      if (data.wrappedKey) setWrappedKey(data.wrappedKey);
    } catch (err) {
      setError(err.message || "Nie udalo sie wykonac operacji");
    } finally {
      setLoading(false);
    }
  };

  const copy = async (value) => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      setError("Nie udalo sie skopiowac tekstu");
    }
  };

  return (
    <div className="bg-dark text-light min-vh-100">
      <main className="container py-5">
        <div className="text-center mb-5">
          <span className="badge bg-primary mb-3">
            Encode / Encrypt / Decode / Decrypt
          </span>
        </div>

        <div className="row g-3 mb-4">
          {tools.map((tool) => (
            <div className="col-6 col-md-3" key={tool.id}>
              <button
                onClick={() => changeMode(tool.id)}
                className={`btn w-100 text-start p-3 border ${
                  mode === tool.id
                    ? "btn-primary border-primary"
                    : "btn-dark border-secondary"
                }`}
              >
                <div className="fs-3 fw-bold mb-2">{tool.symbol}</div>

                <div className="fw-bold">{tool.name}</div>
              </button>
            </div>
          ))}
        </div>

        <div className="row g-4">
          <div className="col-lg-6">
            <div className="card bg-black text-light border-secondary h-100">
              <div className="card-header border-secondary py-3">
                <h5 className="mb-0 fw-bold">{mode.toUpperCase()} Config</h5>
              </div>

              <div className="card-body p-4">
                <label className="form-label">
                  {mode === "decrypt" ? "Zaszyfrowany tekst (HEX)" : "Wprowadz tekst"}
                </label>

                <textarea
                  className="form-control bg-dark text-light border-secondary mb-3"
                  rows="5"
                  placeholder={mode === "decrypt" ? "Szyfrogram w HEX" : "Wpisz tekst"}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                />

                <label className="form-label">Algorytm</label>

                <select
                  className="form-select bg-dark text-light border-secondary mb-3"
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                >
                  {!isCrypto ? (
                    <>
                      <option value="base64">Base64</option>
                      <option value="hex">HEX</option>
                      <option value="url">URL Encoding</option>
                    </>
                  ) : (
                    cryptoAlgorithms.map(([value, label]) => (
                      <option key={value} value={value}>{label}</option>
                    ))
                  )}
                </select>

                {isCrypto && (
                  <>
                    <label className="form-label">
                      {isRsa
                        ? mode === "encrypt" ? "Klucz publiczny RSA (PEM)" : "Klucz prywatny RSA (PEM)"
                        : "Klucz (HEX)"}
                    </label>

                    {isRsa ? (
                      <>
                        <textarea
                          className="form-control bg-dark text-light border-secondary mb-3 font-monospace"
                          rows="5"
                          placeholder={mode === "encrypt" ? "Wklej lub wygeneruj klucz publiczny" : "Wklej klucz prywatny RSA"}
                          value={key}
                          onChange={(e) => setKey(e.target.value)}
                        />
                        {mode === "encrypt" && (
                          <button
                            className="btn btn-outline-primary mb-3"
                            onClick={generateKey}
                            type="button"
                            disabled={loading}
                          >
                            Wygeneruj pare RSA
                          </button>
                        )}
                      </>
                    ) : (
                      <div className="input-group mb-3">
                        <input
                          type="text"
                          className="form-control bg-dark text-light border-secondary"
                          placeholder={`${type === "3des-cbc-hmac-sha256" ? 112 : type.startsWith("aes-") || type.startsWith("aria-") ? Number(type.split("-")[1]) / 4 : 64} znakow HEX`}
                          value={key}
                          onChange={(e) => setKey(e.target.value)}
                        />

                        <button
                          className="btn btn-outline-primary"
                          onClick={generateKey}
                          type="button"
                        >
                          Wygeneruj
                        </button>
                      </div>
                    )}
                  </>
                )}

                {type === "3des-cbc-hmac-sha256" && (
                  <div className="alert alert-warning py-2 small">
                    3DES jest przestarzaly i niezalecany do nowych danych
                  </div>
                )}

                {mode === "decrypt" && (
                  <>
                    <label className="form-label">Nonce (HEX)</label>
                    <input
                      className="form-control bg-dark text-light border-secondary mb-3"
                      value={nonce}
                      onChange={(e) => setNonce(e.target.value)}
                    />

                    {authTag && (
                      <>
                        <label className="form-label">Auth Tag (HEX)</label>
                        <input
                          className="form-control bg-dark text-light border-secondary mb-3"
                          value={authTag}
                          onChange={(e) => setAuthTag(e.target.value)}
                        />
                      </>
                    )}

                    {isRsa && (
                      <>
                        <label className="form-label">Klucz opakowany RSA (Base64)</label>
                        <textarea
                          className="form-control bg-dark text-light border-secondary mb-3 font-monospace"
                          rows="3"
                          value={wrappedKey}
                          onChange={(e) => setWrappedKey(e.target.value)}
                        />
                      </>
                    )}
                  </>
                )}

                {error && <div className="alert alert-danger">{error}</div>}

                <div className="d-flex gap-2 mt-4">
                  <button
                    className="btn btn-primary flex-grow-1"
                    onClick={handleSubmit}
                    disabled={loading}
                  >
                    {loading ? "Ladowanie" : `Uruchom ${mode}`}
                  </button>

                  <button className="btn btn-outline-secondary" onClick={clear}>
                    Wyczysc
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="col-lg-6">
            <div className="card bg-black text-light border-secondary h-100">
              <div className="card-header border-secondary py-3 d-flex justify-content-between align-items-center">
                <h5 className="mb-0 fw-bold">Output</h5>
              </div>

              <div className="card-body p-4">
                {result !== "" ? (
                  <>
                    <label className="form-label text-secondary">Wynik</label>

                    <textarea
                      className="form-control bg-dark text-success border-secondary font-monospace"
                      rows="7"
                      readOnly
                      value={result}
                    />

                    <button
                      className="btn btn-outline-primary w-100 mt-3"
                      onClick={() => copy(result)}
                    >
                      Skopiuj
                    </button>

                    {mode === "encrypt" && (
                      <button
                        className="btn btn-primary w-100 mt-2"
                        onClick={() => changeMode("decrypt")}
                      >
                        Przejdz do odszyfrowania
                      </button>
                    )}

                    {mode === "encrypt" && nonce && (
                      <div className="mt-4">
                        <label className="form-label">Nonce (HEX)</label>

                        <input
                          className="form-control bg-dark text-light border-secondary"
                          value={nonce}
                          readOnly
                        />

                        <button
                          className="btn btn-outline-secondary btn-sm mt-2"
                          onClick={() => copy(nonce)}
                        >
                          Skopiuj nonce
                        </button>

                        {authTag && (
                          <div className="mt-3">
                            <label className="form-label">
                              Tag
                            </label>
                            <input
                              className="form-control bg-dark text-light border-secondary"
                              value={authTag}
                              readOnly
                            />
                          </div>
                        )}
                      </div>
                    )}

                    {mode === "encrypt" && isRsa && privateKey && (
                      <div className="mt-4">
                        <label className="form-label">Klucz prywatny RSA (zachowaj)</label>
                        <textarea
                          className="form-control bg-dark text-light border-secondary font-monospace"
                          rows="5"
                          value={privateKey}
                          readOnly
                        />
                        <button
                          className="btn btn-outline-secondary btn-sm mt-2"
                          onClick={() => copy(privateKey)}
                        >
                          Skopiuj klucz prywatny
                        </button>
                      </div>
                    )}

                    {mode === "encrypt" && isRsa && wrappedKey && (
                      <div className="mt-4">
                        <label className="form-label">Klucz opakowany RSA (Base64)</label>
                        <textarea
                          className="form-control bg-dark text-light border-secondary font-monospace"
                          rows="3"
                          value={wrappedKey}
                          readOnly
                        />
                        <button
                          className="btn btn-outline-secondary btn-sm mt-2"
                          onClick={() => copy(wrappedKey)}
                        >
                          Skopiuj klucz opakowany
                        </button>
                      </div>
                    )}

                    <div className="mt-4">
                      <label className="form-label text-secondary">
                        API
                      </label>

                      <pre className="bg-dark text-info p-3 rounded small overflow-auto">
                        {JSON.stringify(responseData, null, 2)}
                      </pre>
                    </div>
                  </>
                ) : (
                  <div className="text-center py-5">
                    <div className="display-4 text-secondary mb-3">{"{ }"}</div>

                    <h5>Puste</h5>

                    <p className="text-secondary small">
                      Wprowadz text i wybierz
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
