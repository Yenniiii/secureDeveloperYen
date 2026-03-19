window.boardSkeleton = {
  sessionKey: "boardSkeleton.session",
  selectedPostKey: "boardSkeleton.selectedPostId",

  getSession() {
    const raw = window.localStorage.getItem(this.sessionKey);
    return raw ? JSON.parse(raw) : null;
  },

  setSession(session) {
    window.localStorage.setItem(this.sessionKey, JSON.stringify(session));
  },

  updateStoredUser(user) {
    const session = this.getSession();
    if (!session) return;
    session.user = user;
    this.setSession(session);
  },

  clearSession() {
    window.localStorage.removeItem(this.sessionKey);
    this.clearSelectedPostId();
  },

  getSelectedPostId() {
    return window.localStorage.getItem(this.selectedPostKey);
  },

  setSelectedPostId(postId) {
    window.localStorage.setItem(this.selectedPostKey, String(postId));
  },

  clearSelectedPostId() {
    window.localStorage.removeItem(this.selectedPostKey);
  },

  routeTo(hash) {
    window.location.hash = hash;
  },

  async request(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body) {
      headers["Content-Type"] = "application/json";
    }

    const session = this.getSession();
    if (session?.token) {
      headers.Authorization = session.token;
    }

    const response = await fetch(path, {
      ...options,
      headers,
      credentials: "include",
    });

    let payload;
    try {
      payload = await response.json();
    } catch (error) {
      payload = { message: "JSON 응답이 없습니다.", error: error.message };
    }

    return { status: response.status, payload };
  },

  renderConsole(data) {
    const output = document.querySelector("#console-output");
    if (!output) return;
    output.textContent = JSON.stringify(data, null, 2);
  },

  updateSessionStatus() {
    const box = document.querySelector("#session-status");
    if (!box) return;

    const session = this.getSession();
    if (!session?.user) {
      box.textContent = "아직 Authorization 토큰이 없습니다.";
      return;
    }

    const user = session.user;
    const balance = Number(user.balance || 0).toLocaleString("ko-KR");
    const scope = user.is_admin ? "관리자" : "일반 사용자";
    box.textContent = `${user.name || user.username} 로그인됨, 권한 ${scope}, Authorization 헤더 준비됨, 잔액 ${balance}`;
  },
};

document.addEventListener("DOMContentLoaded", () => {
  window.boardSkeleton.updateSessionStatus();
});
