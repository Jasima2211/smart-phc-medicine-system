// Smart PHC — Client-side interactions and dashboard scripts

document.addEventListener("DOMContentLoaded", function () {
  // 1. Initialize Auto-dismissing alerts after 5 seconds
  const autoAlerts = document.querySelectorAll(".alert-dismissible");
  autoAlerts.forEach(function (alertEl) {
    setTimeout(function () {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
      if (bsAlert) {
        bsAlert.close();
      }
    }, 6000);
  });

  // 2. Client-side Live Table Filter
  const tableSearchInput = document.getElementById("tableSearchInput");
  if (tableSearchInput) {
    tableSearchInput.addEventListener("keyup", function () {
      const filter = tableSearchInput.value.toLowerCase().trim();
      const targetTableId = tableSearchInput.getAttribute("data-target-table") || "searchableTable";
      const table = document.getElementById(targetTableId);
      if (!table) return;

      const rows = table.querySelectorAll("tbody tr");
      rows.forEach(function (row) {
        const text = row.textContent.toLowerCase();
        if (text.indexOf(filter) > -1) {
          row.style.display = "";
        } else {
          row.style.display = "none";
        }
      });
    });
  }

  // 3. Stock Action Modals (Receive, Issue, Adjust)
  const stockModal = document.getElementById("stockActionModal");
  if (stockModal) {
    stockModal.addEventListener("show.bs.modal", function (event) {
      const button = event.relatedTarget;
      if (!button) return;

      const action = button.getAttribute("data-action"); // 'receive', 'issue', 'adjust'
      const medId = button.getAttribute("data-med-id");
      const medName = button.getAttribute("data-med-name");
      const usable = button.getAttribute("data-usable") || "0";

      const titleEl = document.getElementById("stockModalTitle");
      const formEl = document.getElementById("stockModalForm");
      const actionTypeInput = document.getElementById("modalActionType");
      const medIdInput = document.getElementById("modalMedicineId");
      const medNameDisplay = document.getElementById("modalMedNameDisplay");
      const usableDisplay = document.getElementById("modalCurrentUsable");
      const qtyInput = document.getElementById("modalQuantityInput");
      const qtyLabel = document.getElementById("modalQuantityLabel");
      const notesInput = document.getElementById("modalNotesInput");
      const submitBtn = document.getElementById("stockModalSubmitBtn");

      if (actionTypeInput) actionTypeInput.value = action;
      if (medIdInput) medIdInput.value = medId;
      if (medNameDisplay) medNameDisplay.textContent = medName;
      if (usableDisplay) usableDisplay.textContent = usable;
      if (qtyInput) {
        qtyInput.value = "";
        qtyInput.focus();
      }
      if (notesInput) notesInput.value = "";

      if (action === "receive") {
        titleEl.textContent = "Receive Inbound Stock";
        qtyLabel.textContent = "Quantity to Receive (Units)";
        if (formEl) formEl.action = "/phc/stock/receive";
        submitBtn.className = "btn btn-success";
        submitBtn.textContent = "Confirm Stock Receipt";
        qtyInput.max = "";
      } else if (action === "issue") {
        titleEl.textContent = "Issue Stock to Outpatient / Ward";
        qtyLabel.textContent = "Quantity to Dispense (Units)";
        if (formEl) formEl.action = "/phc/stock/issue";
        submitBtn.className = "btn btn-danger";
        submitBtn.textContent = "Confirm Stock Dispensing";
        qtyInput.max = usable;
      } else if (action === "adjust") {
        titleEl.textContent = "Correct Inventory (Stock Adjustment)";
        qtyLabel.textContent = "New Verified Usable Stock (Counted)";
        if (formEl) formEl.action = "/phc/stock/adjust";
        submitBtn.className = "btn btn-primary";
        submitBtn.textContent = "Save Count Correction";
        qtyInput.value = usable;
        qtyInput.max = "";
      }
    });
  }

  // 4. Safe confirmation prompts on destructive or consequential actions
  const confirmForms = document.querySelectorAll("form[data-confirm]");
  confirmForms.forEach(function (form) {
    form.addEventListener("submit", function (e) {
      const msg = form.getAttribute("data-confirm") || "Are you sure you want to proceed with this operation?";
      if (!window.confirm(msg)) {
        e.preventDefault();
      }
    });
  });
});

// Helper for rendering Chart.js on dashboards
function renderPhcStockChart(canvasId, labels, dataCounts, backgroundColors) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || typeof Chart === "undefined") return;

  new Chart(canvas.getContext("2d"), {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [
        {
          data: dataCounts,
          backgroundColor: backgroundColors || ["#dc2626", "#d97706", "#0284c7", "#16a34a"],
          borderWidth: 2,
          borderColor: "#ffffff",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            boxWidth: 12,
            font: { size: 12 },
          },
        },
      },
      cutout: "68%",
    },
  });
}
