@preconcurrency import AVFoundation
import SwiftUI
import UIKit

struct TOTPScannerView: UIViewControllerRepresentable {
    let onResult: (Result<String, Error>) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.onResult = onResult
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ uiViewController: ScannerViewController, coordinator: ()) {
        uiViewController.stop()
    }
}

private enum ScannerError: LocalizedError {
    case permissionDenied, unavailable
    var errorDescription: String? {
        switch self {
        case .permissionDenied: "Camera access is off. Enable it for NoirVault in iOS Settings, or enter the setup key manually."
        case .unavailable: "The camera is unavailable. Enter the authenticator setup key manually."
        }
    }
}

final class ScannerViewController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    var onResult: ((Result<String, Error>) -> Void)?
    private let session = AVCaptureSession()
    private var finished = false
    private let captureQueue = DispatchQueue(label: "com.Tokyo.noirvault.scanner")

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            Task { @MainActor [weak self] in
                guard let self, !self.finished else { return }
                if granted { self.configure() }
                else { self.finish(.failure(ScannerError.permissionDenied)) }
            }
        }
    }

    private func configure() {
        do {
            guard let camera = AVCaptureDevice.default(for: .video) else { throw ScannerError.unavailable }
            let input = try AVCaptureDeviceInput(device: camera)
            guard session.canAddInput(input) else { throw ScannerError.unavailable }
            session.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard session.canAddOutput(output) else { throw ScannerError.unavailable }
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let preview = AVCaptureVideoPreviewLayer(session: session)
            preview.videoGravity = .resizeAspectFill
            preview.frame = view.bounds
            view.layer.addSublayer(preview)
            captureQueue.async { [session] in session.startRunning() }
        } catch {
            finish(.failure(error))
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        (view.layer.sublayers?.first as? AVCaptureVideoPreviewLayer)?.frame = view.bounds
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let value = (metadataObjects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else { return }
        finish(.success(value))
    }

    private func finish(_ result: Result<String, Error>) {
        guard !finished else { return }
        stop()
        onResult?(result)
    }

    func stop() {
        finished = true
        captureQueue.async { [session] in if session.isRunning { session.stopRunning() } }
    }
}
