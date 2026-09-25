import urllib.request
import json
import time

def test_chat():
    print("Testing /api/threat-query/chat/stream...")
    payload = json.dumps({
        "question": "What specific event IDs detect this pivot?",
        "chat_history": [],
        "facts": [
            "(APT29:ThreatActor)-[:EXPLOITS]->(CVE-2021-44228:Vulnerability)",
            "(CVE-2021-44228)-[:TARGETS]->(k8s-auth-ingress-gateway:EnterpriseService)"
        ],
        "base_report": "APT29 exploits Log4Shell on k8s-auth-ingress-gateway to compromise payment-token-vault."
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/threat-query/chat/stream",
        data=payload,
        headers={"Content-Type": "application/json"}
    )

    t0 = time.time()
    chunks = 0
    full_text = ""
    with urllib.request.urlopen(req) as resp:
        for line in resp:
            line_str = line.decode("utf-8").strip()
            if line_str.startswith("data: "):
                raw = line_str[6:]
                try:
                    data = json.loads(raw)
                    if "text" in data:
                        chunks += 1
                        full_text += data["text"]
                        if chunks <= 3:
                            print(f"Chunk {chunks}: {data['text']!r}")
                    if data.get("done"):
                        print("Stream DONE signal received.")
                        break
                except Exception as e:
                    print("JSON decode error:", e)

    elapsed = round(time.time() - t0, 3)
    print(f"Total chunks: {chunks} | Elapsed: {elapsed}s")
    print(f"Full text length: {len(full_text)} characters")
    print(f"Sample response:\n{full_text[:200]}...")

if __name__ == "__main__":
    test_chat()
