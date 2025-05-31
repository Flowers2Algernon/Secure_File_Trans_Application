/**
 * @jest-environment jsdom
 */

describe('UI Components Tests', () => {
    // 在每个测试之前重置DOM
    beforeEach(() => {
      document.body.innerHTML = `
        <form id="myForm">
          <button id="cancelBtn">Cancel</button>
        </form>
        <div class="faq-container">
          <div class="faq-item">
            <div class="faq-toggle">Question 1</div>
            <div class="faq-content" style="display: none;">Answer 1</div>
          </div>
          <div class="faq-item">
            <div class="faq-toggle">Question 2</div>
            <div class="faq-content" style="display: none;">Answer 2</div>
          </div>
        </div>
      `;
      
      // 模拟window.location
      delete window.location;
      window.location = { href: '' };
      
      // 添加事件监听器
      const cancelBtn = document.getElementById('cancelBtn');
      cancelBtn.addEventListener('click', function () {
        window.location.href = '#';
      });
      
      const faqToggles = document.querySelectorAll('.faq-toggle');
      faqToggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
          const content = this.nextElementSibling;
          content.style.display = content.style.display === 'none' ? 'block' : 'none';
        });
      });
    });
  
    // unit test
    test('when click cancel, it should direct to #', () => {
      const cancelBtn = document.getElementById('cancelBtn');
      cancelBtn.click();
      expect(window.location.href).toBe('#');
    });
  
    // Integration test
    test('Click FAQ should display the content', () => {
      const firstToggle = document.querySelectorAll('.faq-toggle')[0];
      const firstContent = firstToggle.nextElementSibling;
      
      // initial state
      expect(firstContent.style.display).toBe('none');
      
      // click to show
      firstToggle.click();
      expect(firstContent.style.display).toBe('block');
      
      // double click to hide
      firstToggle.click();
      expect(firstContent.style.display).toBe('none');
    });
  
    // Regression Test
    test('Ensure FAQ component functionality is not affected by other changes', () => {
      const faqToggle = document.querySelectorAll('.faq-toggle')[1];
      const faqContent = faqToggle.nextElementSibling;
      
      // Initial state
      expect(faqContent.style.display).toBe('none');
      
      // Click to show
      faqToggle.click();
      expect(faqContent.style.display).toBe('block');
      
      // Simulate changes to other components
      document.getElementById('cancelBtn').style.backgroundColor = 'red';
      
      // Ensure FAQ component still works properly
      faqToggle.click();
      expect(faqContent.style.display).toBe('none');
    });
  });