/* [AI生成] Claudeが作成（AI利用記録 #7） */
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) {
        e.preventDefault();
      }
    });
  });

  document.querySelectorAll("form").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (e.defaultPrevented) return;
      if (form.dataset.submitting === "1") {
        e.preventDefault();
        return;
      }
      form.dataset.submitting = "1";
      form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(function (btn) {
        btn.disabled = true;
      });
      setTimeout(function () {
        form.dataset.submitting = "0";
        form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(function (btn) {
          btn.disabled = false;
        });
      }, 10000);
    });
  });

  var category = document.getElementById("category");
  var attendance = document.getElementById("attendance-field");
  if (category && attendance) {
    var toggle = function () {
      attendance.classList.toggle("d-none", category.value !== "attendance");
    };
    category.addEventListener("change", toggle);
    toggle();
  }
});
