document.addEventListener('DOMContentLoaded', () => {
    const searchBar = document.getElementById('search');
    const container = document.querySelector('.product-grid');
    const productCards = Array.from(container.querySelectorAll('.product-card'));

    searchBar.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();

        const matches = [];
        const nonMatches = [];

        productCards.forEach(card => {
            const visibleText = card.textContent.toLowerCase();
            const hiddenText = card.querySelector('.hidden-data')?.textContent.toLowerCase() || '';
            const combined = visibleText + ' ' + hiddenText;

            if (combined.includes(searchTerm)) {
                card.style.display = '';  // show
                matches.push(card);
            } else {
                card.style.display = 'none';  // hide
                nonMatches.push(card);
            }
        });

        // Clear and reorder the container
        container.innerHTML = '';
        matches.forEach(card => container.appendChild(card));
        nonMatches.forEach(card => container.appendChild(card));
    });



    // --- Slideshow functionality ---
    let slideIndex = 0;
    let slideTimer;

    function showSlides() {
        const slides = document.getElementsByClassName("mySlides");
        const dots = document.getElementsByClassName("dot");
        for (let i = 0; i < slides.length; i++) {
            slides[i].style.display = "none";
        }

        slideIndex++;
        if (slideIndex > slides.length) { slideIndex = 1; }
        if (slideIndex < 1) { slideIndex = slides.length; }

        if (slides.length > 0) {
            slides[slideIndex - 1].style.display = "block";
            if (dots.length > 0) {
                for (let i = 0; i < dots.length; i++) {
                    dots[i].classList.remove("active");
                }
                dots[slideIndex - 1].classList.add("active");
            }
        }

        // Auto-slide every 4 seconds
        slideTimer = setTimeout(showSlides, 4000);
    }

    window.plusSlides = function(n) {
        clearTimeout(slideTimer); // Stop auto sliding on manual click
        slideIndex += n - 1;
        showSlides();
    }

    window.currentSlide = function(n) {
        clearTimeout(slideTimer);
        slideIndex = n - 1;
        showSlides();
    }

    showSlides();
});
let slideIndex = 0;
showSlides();

function showSlides() {
    let i;
    let slides = document.getElementsByClassName("mySlides");
    let dots = document.getElementsByClassName("dot");
    for (i = 0; i < slides.length; i++) {
        slides[i].style.display = "none";  
    }
    slideIndex++;
    if (slideIndex > slides.length) { slideIndex = 1; }    
    for (i = 0; i < dots.length; i++) {
        dots[i].className = dots[i].className.replace(" active", "");
    }
    if (slides.length > 0) {
        slides[slideIndex - 1].style.display = "block";  
        dots[slideIndex - 1].className += " active";
    }
    setTimeout(showSlides, 2000); // Change image every 2 seconds
}

  function autoSubmit() {
    document.getElementById("ratingForm").submit();
  }


function refreshBack() {
    window.location.href = document.referrer; // Go back and reload
}

function scrollProducts(sliderId, direction) {
    const container = document.getElementById(sliderId);
    const cardWidth = container.querySelector('div').offsetWidth + 20; // card width + gap
    container.scrollBy({
        left: direction * cardWidth * 3, // scroll by 3 cards
        behavior: 'smooth'
    });
}

// function showSection(id) {
//     // Hide all sections
//     document.querySelectorAll('.tab-section').forEach(section => {
//         section.style.display = 'none';
//     });

//     // Remove 'active' class from all buttons
//     document.querySelectorAll('.tab-btn').forEach(btn => {
//         btn.classList.remove('active');
//     });

//     // Show the selected section
//     const target = document.getElementById(id);
//     if (target) {
//         target.style.display = 'block';
//     }

//     // Set active class to the clicked button
//     const buttons = document.querySelectorAll('.tab-btn');
//     buttons.forEach((btn) => {
//         if (btn.getAttribute('onclick')?.includes(id)) {
//             btn.classList.add('active');
//         }
//     });
// }

// // Optional: Show the first tab by default
// window.onload = function () {
//     showSection('add-product-section');
// };




function showSection(id) {
    // Hide all sections
    document.querySelectorAll('.tab-section').forEach(section => {
        section.style.display = 'none';
    });

    // Remove 'active' class from all buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show the selected section
    const target = document.getElementById(id);
    if (target) {
        target.style.display = 'block';

        // ✅ Auto-show sub-section when "company-list" is selected
        if (id === 'company-list') {
            showSubSection('user-details');
        }
    }

    // Set active class to the clicked button
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach((btn) => {
        if (btn.getAttribute('onclick')?.includes(id)) {
            btn.classList.add('active');
        }
    });
}

// 👉 Handles sub-sections inside company-list
function showSubSection(subId) {
    const subSections = document.querySelectorAll('#company-list .tab-section');
    subSections.forEach(sub => {
        sub.style.display = 'none';
    });

    const subTarget = document.getElementById(subId);
    if (subTarget) {
        subTarget.style.display = 'block';
    }
}

// Optional: Show the first tab by default
window.onload = function () {
    showSection('add-product-section');
};







function updateMailNotification(newCount) {
    const badge = document.getElementById('mail-notification');
    if (newCount > 0) {
        badge.innerText = newCount;
        badge.style.display = 'inline-block';
    } else {
        badge.style.display = 'none';
    }
}










