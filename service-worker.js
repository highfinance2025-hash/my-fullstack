// Service Worker for HTLand PWA - Optimized

const CACHE_NAME = 'htland-v3';
const OFFLINE_URL = '/offline.html';

// Static assets
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/css/style.css',
    '/js/main.js',
    '/manifest.json'
];

// Dynamic assets (APIs)
const DYNAMIC_ASSETS = [
    '/api/products',
    '/api/categories'
];

// Install event
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('[Service Worker] Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => self.skipWaiting())
    );
});

// Activate event
self.addEventListener('activate', event => {
    event.waitUntil(
        Promise.all([
            // Clean old caches
            caches.keys().then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== CACHE_NAME) {
                            console.log('[Service Worker] Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            }),
            // Claim clients immediately
            self.clients.claim()
        ])
    );
});

// Fetch event
self.addEventListener('fetch', event => {
    // Skip non-GET requests
    if (event.request.method !== 'GET') return;
    
    // Skip chrome-extension requests
    if (event.request.url.startsWith('chrome-extension://')) return;
    
    const requestUrl = new URL(event.request.url);
    
    // API requests - Network First strategy
    if (requestUrl.pathname.startsWith('/api/')) {
        event.respondWith(
            fetch(event.request)
                .then(response => {
                    // Cache the API response
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME)
                        .then(cache => cache.put(event.request, responseClone));
                    return response;
                })
                .catch(() => {
                    // If offline, try to get from cache
                    return caches.match(event.request);
                })
        );
        return;
    }
    
    // Static assets - Cache First strategy
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Return cached response if found
                if (response) {
                    return response;
                }
                
                // Clone the request
                const fetchRequest = event.request.clone();
                
                return fetch(fetchRequest)
                    .then(response => {
                        // Check if valid response
                        if (!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }
                        
                        // Clone the response
                        const responseToCache = response.clone();
                        
                        // Cache the new response
                        caches.open(CACHE_NAME)
                            .then(cache => {
                                cache.put(event.request, responseToCache);
                            });
                        
                        return response;
                    })
                    .catch(() => {
                        // If offline and page request, show offline page
                        if (event.request.mode === 'navigate') {
                            return caches.match(OFFLINE_URL) || 
                                   new Response('شما آفلاین هستید. لطفاً اتصال اینترنت خود را بررسی کنید.');
                        }
                        
                        // Return offline data for other requests
                        return new Response(JSON.stringify({
                            error: 'شما آفلاین هستید',
                            message: 'لطفاً اتصال اینترنت خود را بررسی کنید'
                        }), {
                            headers: { 'Content-Type': 'application/json' }
                        });
                    });
            })
    );
});

// Push notifications
self.addEventListener('push', event => {
    if (!event.data) return;
    
    const data = event.data.json();
    
    const options = {
        body: data.body || 'Notification from HTLand',
        icon: '/images/logo-192.png',
        badge: '/images/badge.png',
        vibrate: [100, 50, 100],
        data: {
            dateOfArrival: Date.now(),
            url: data.url || '/'
        },
        actions: [
            {
                action: 'view',
                title: 'مشاهده',
                icon: '/images/view.png'
            },
            {
                action: 'close',
                title: 'بستن',
                icon: '/images/close.png'
            }
        ]
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title || 'HTLand', options)
    );
});

// Notification click
self.addEventListener('notificationclick', event => {
    event.notification.close();
    
    if (event.action === 'close') {
        return;
    }
    
    event.waitUntil(
        clients.matchAll({ type: 'window' })
            .then(clientList => {
                for (const client of clientList) {
                    if (client.url === '/' && 'focus' in client) {
                        return client.focus();
                    }
                }
                
                if (clients.openWindow) {
                    return clients.openWindow(event.notification.data.url || '/');
                }
            })
    );
});

// Background sync
self.addEventListener('sync', event => {
    if (event.tag === 'sync-orders') {
        event.waitUntil(syncOrders());
    }
});

async function syncOrders() {
    // Implement background sync logic here
    console.log('[Service Worker] Syncing orders in background...');
    
    // Example: Sync pending orders
    try {
        // Get pending orders from IndexedDB
        // Sync with server
        // Remove from IndexedDB if successful
    } catch (error) {
        console.error('[Service Worker] Background sync failed:', error);
    }
}

// Periodic sync (for newer browsers)
if ('periodicSync' in self.registration) {
    self.addEventListener('periodicsync', event => {
        if (event.tag === 'update-content') {
            event.waitUntil(updateContent());
        }
    });
}

async function updateContent() {
    console.log('[Service Worker] Periodic content update');
    // Update cached content periodically
}