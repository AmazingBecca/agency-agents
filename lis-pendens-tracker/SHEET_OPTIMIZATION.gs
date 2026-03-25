/**
 * SHEET OPTIMIZATION SYSTEM - CLEAN DEPLOYMENT VERSION
 * Copy this entire file to: Extensions > Apps Script in your sheet
 * Status: PRODUCTION READY - NO EMOJIS (compatible with all editors)
 */

// ============================================================================
// MENU SYSTEM - Appears when sheet opens
// ============================================================================

function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('Deal Tools')
    .addItem('RUN FULL OPTIMIZATION', 'runFullOptimization')
    .addSeparator()
    .addItem('1. Freeze Panes', 'setupFreezePanes')
    .addItem('2. Create Apartments Sheet', 'createApartmentSection')
    .addItem('3. Audit Missing Columns', 'auditMissingColumns')
    .addItem('4. Load Court Data', 'integrateFloridaCourtAPI')
    .addItem('5. Apply Styling', 'applyStrikeStyle')
    .addItem('6. Setup Notifications', 'setupNotificationSystem')
    .addToUi();
}

function runFullOptimization() {
  try {
    setupFreezePanes();
    createApartmentSection();
    auditMissingColumns();
    applyStrikeStyle();
    
    const ui = SpreadsheetApp.getUi();
    ui.alert('SUCCESS: All optimizations deployed!\n\nYour sheet now has:\n- Frozen headers\n- Apartment tracking\n- Professional styling\n- Column audit\n\nCheck console for details.');
  } catch(e) {
    SpreadsheetApp.getUi().alert('ERROR: ' + e.toString());
  }
}

// ============================================================================
// 1. FREEZE PANES SETUP
// ============================================================================

function setupFreezePanes() {
  const sheet = SpreadsheetApp.getActiveSheet();
  
  // Freeze row 1 (headers)
  sheet.setFrozenRows(1);
  
  // Freeze columns A-B (Priority, Status)
  sheet.setFrozenColumns(2);
  
  console.log('[FREEZE] Headers and key columns frozen');
}

// ============================================================================
// 2. CREATE APARTMENT/MULTI-UNIT TRACKING SHEET
// ============================================================================

function createApartmentSection() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Check if apartment sheet exists
  let apartmentSheet = ss.getSheetByName('Apartments');
  if (!apartmentSheet) {
    apartmentSheet = ss.insertSheet('Apartments', ss.getSheets().length);
  }
  
  // Set headers for apartment tracking
  const headers = [
    'Priority',
    'Status',
    'Property Address',
    'City',
    'County',
    'Total Units',
    'Occupied Units',
    'Vacancy Rate %',
    'Avg Rent/Unit',
    'Monthly Income',
    'Annual Income',
    'Cap Rate %',
    'ARV',
    'Rehab Cost',
    'Profit Potential',
    'Notes'
  ];
  
  // Clear existing data
  apartmentSheet.clear();
  
  // Add headers
  apartmentSheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  
  // Format header row - Strike branding
  const headerRange = apartmentSheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground('#1F4D78');
  headerRange.setFontColor('#FFFFFF');
  headerRange.setFontWeight('bold');
  headerRange.setFontSize(11);
  
  // Add sample data
  const sampleData = [
    ['HOT', 'Analyzing', '2845 Oak Street', 'Tampa', 'Hillsborough', 8, 7, '12.5%', '850', '5950', '71400', '8.2%', '520000', '45000', '75000', 'Good condition'],
    ['MEDIUM', 'Pending', '5621 Palmetto Ave', 'Jacksonville', 'Duval', 6, 4, '33.3%', '725', '2900', '34800', '4.1%', '380000', '65000', '18000', 'Needs work'],
    ['COLD', 'Follow Up', '3100 Clearview Dr', 'Miami', 'Miami-Dade', 12, 9, '25%', '950', '8550', '102600', '9.5%', '850000', '120000', '105000', 'Strong tenant base']
  ];
  
  apartmentSheet.getRange(2, 1, sampleData.length, headers.length).setValues(sampleData);
  
  // Format sample data rows
  for (let i = 0; i < sampleData.length; i++) {
    const row = i + 2;
    apartmentSheet.getRange(row, 1, 1, headers.length).setBackground('#F5F5F5');
  }
  
  // Auto-fit columns
  for (let i = 1; i <= headers.length; i++) {
    apartmentSheet.autoResizeColumn(i);
  }
  
  console.log('[APARTMENTS] New tracking sheet created with 3 sample properties');
}

// ============================================================================
// 3. AUDIT MISSING COLUMNS
// ============================================================================

function auditMissingColumns() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  
  // Required columns for complete tracking
  const requiredColumns = [
    'Priority',
    'Status',
    'Over 55+ Community',
    'Case #',
    'Case Status',
    'Next Hearing',
    'Front Photo URL',
    'Owner Name',
    'Owner Phone'
  ];
  
  const missingColumns = [];
  
  for (const col of requiredColumns) {
    if (!headers.includes(col)) {
      missingColumns.push(col);
    }
  }
  
  if (missingColumns.length > 0) {
    console.log('[AUDIT] Missing columns: ' + missingColumns.join(', '));
    console.log('[AUDIT] Adding missing columns to sheet');
    addMissingColumns(missingColumns);
  } else {
    console.log('[AUDIT] All required columns present');
  }
  
  return missingColumns;
}

function addMissingColumns(missingCols) {
  const sheet = SpreadsheetApp.getActiveSheet();
  const lastCol = sheet.getLastColumn();
  
  missingCols.forEach((colName, index) => {
    const targetCol = lastCol + index + 1;
    const cell = sheet.getRange(1, targetCol);
    cell.setValue(colName);
    cell.setBackground('#FF9800');
    cell.setFontWeight('bold');
    cell.setFontColor('white');
  });
  
  console.log('[AUDIT] Added ' + missingCols.length + ' missing columns');
}

// ============================================================================
// 4. FLORIDA COURT API INTEGRATION
// ============================================================================

function integrateFloridaCourtAPI() {
  const sheet = SpreadsheetApp.getActiveSheet();
  const data = sheet.getDataRange().getValues();
  
  // Find columns for case data
  const headers = data[0];
  const caseCol = headers.indexOf('Case #') + 1;
  const caseStatusCol = headers.indexOf('Case Status') + 1;
  
  if (caseCol === 0 || caseStatusCol === 0) {
    console.log('[COURT API] Case # or Case Status columns not found');
    console.log('[COURT API] Run "Audit Missing Columns" first');
    return;
  }
  
  // Process up to 50 cases (API rate limiting)
  let processed = 0;
  for (let i = 1; i < Math.min(data.length, 51); i++) {
    const caseNumber = data[i][caseCol - 1];
    
    if (caseNumber && caseNumber.toString().trim() !== '') {
      try {
        // Miami-Dade Clerk API (public endpoint)
        const url = 'https://www2.miamidadeclerk.gov/api/CaseSearch?caseNumber=' + 
                   encodeURIComponent(caseNumber);
        
        const response = UrlFetchApp.fetch(url, {
          muteHttpExceptions: true,
          timeout: 5000
        });
        
        if (response.getResponseCode() === 200) {
          try {
            const caseData = JSON.parse(response.getContentText());
            
            if (caseData.status) {
              sheet.getRange(i + 1, caseStatusCol).setValue(caseData.status);
            }
            
            processed++;
          } catch(e) {
            console.log('[COURT API] Parse error for case ' + caseNumber);
          }
        }
      } catch(e) {
        console.log('[COURT API] Error fetching ' + caseNumber + ': ' + e);
      }
    }
  }
  
  console.log('[COURT API] Updated ' + processed + ' case records');
}

// ============================================================================
// 5. STRIKE DASHBOARD STYLING
// ============================================================================

function applyStrikeStyle() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Apply to all sheets
  const sheets = ss.getSheets();
  
  sheets.forEach(function(sheet) {
    const data = sheet.getDataRange().getValues();
    if (data.length === 0) return;
    
    // Format header row
    const headerRange = sheet.getRange(1, 1, 1, sheet.getLastColumn());
    headerRange.setBackground('#1F4D78');
    headerRange.setFontColor('#FFFFFF');
    headerRange.setFontWeight('bold');
    headerRange.setFontSize(11);
    
    // Format data rows with alternating colors
    for (let i = 1; i < data.length; i++) {
      const row = i + 1;
      const rowRange = sheet.getRange(row, 1, 1, sheet.getLastColumn());
      
      if (i % 2 === 0) {
        rowRange.setBackground('#FFFFFF');
      } else {
        rowRange.setBackground('#F9F9F9');
      }
    }
    
    // Highlight priority column if exists
    const headers = data[0];
    const priorityCol = headers.indexOf('Priority') + 1;
    
    if (priorityCol > 0) {
      for (let i = 1; i < Math.min(data.length, 100); i++) {
        const priority = data[i][priorityCol - 1];
        const cell = sheet.getRange(i + 1, priorityCol);
        
        if (priority === 'HOT') {
          cell.setBackground('#FF4444');
          cell.setFontColor('white');
        } else if (priority === 'MEDIUM') {
          cell.setBackground('#FF9800');
          cell.setFontColor('white');
        } else if (priority === 'COLD') {
          cell.setBackground('#4CAF50');
          cell.setFontColor('white');
        }
      }
    }
  });
  
  console.log('[STYLING] Strike branding applied to all sheets');
}

// ============================================================================
// 6. NOTIFICATION SYSTEM SETUP
// ============================================================================

function setupNotificationSystem() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  
  // Check if notification sheet exists
  let notifSheet = ss.getSheetByName('Notifications');
  if (!notifSheet) {
    notifSheet = ss.insertSheet('Notifications', 0);
  }
  
  // Headers for notification log
  const headers = [
    'Timestamp',
    'Property',
    'Event Type',
    'Status',
    'Message',
    'Action Taken',
    'Notes'
  ];
  
  // Clear and setup
  notifSheet.clear();
  notifSheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  
  // Format header
  const headerRange = notifSheet.getRange(1, 1, 1, headers.length);
  headerRange.setBackground('#FF9800');
  headerRange.setFontColor('white');
  headerRange.setFontWeight('bold');
  
  // Set column widths
  notifSheet.setColumnWidth(1, 180);
  notifSheet.setColumnWidth(2, 200);
  notifSheet.setColumnWidth(3, 150);
  notifSheet.setColumnWidth(4, 100);
  
  // Freeze header
  notifSheet.setFrozenRows(1);
  
  console.log('[NOTIFICATIONS] System created - ready to log events');
}

// ============================================================================
// UTILITY: Send email notification
// ============================================================================

function sendNotification(subject, message) {
  try {
    const email = Session.getActiveUser().getEmail();
    MailApp.sendEmail(email, subject, message);
    console.log('[MAIL] Notification sent to ' + email);
  } catch(e) {
    console.log('[MAIL] Error: ' + e);
  }
}

// ============================================================================
// END OF SCRIPT
// ============================================================================
