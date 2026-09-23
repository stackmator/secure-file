use secure_file::{Error, SecureFile};
use std::sync::{Arc, Barrier};

#[test]
fn concurrent_create_only_one_succeeds() {
    const THREADS: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("race"));
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                SecureFile::create(path.as_ref()).map(|_| ())
            })
        })
        .collect();

    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    let successes = results.iter().filter(|result| result.is_ok()).count();
    let already_exists = results
        .iter()
        .filter(|result| matches!(result, Err(Error::AlreadyExists)))
        .count();

    assert_eq!(successes, 1, "results: {results:?}");
    assert_eq!(already_exists, THREADS - 1, "results: {results:?}");
}

#[test]
fn concurrent_write_private_leaves_a_private_file() {
    const THREADS: usize = 8;

    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().join("token"));
    let barrier = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                secure_file::write_private(path.as_ref(), [b'0' + i as u8])
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    let file = SecureFile::open(path.as_ref()).unwrap();
    assert!(file.is_private().unwrap());
    assert_eq!(secure_file::read_private(path.as_ref()).unwrap().len(), 1);
}
